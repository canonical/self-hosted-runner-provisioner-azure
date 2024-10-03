import base64
import dataclasses
import datetime
import enum
import hashlib
import hmac
import json
import logging
import os
import re
import string
import time

import azure.core.exceptions
import azure.functions as func
import azure.identity
import azure.keyvault.keys.crypto as crypto
import azure.mgmt.costmanagement
import azure.mgmt.costmanagement.models as cost_models
import azure.mgmt.dns.v2018_05_01
import azure.mgmt.dns.v2018_05_01.models as dns_models
import azure.mgmt.network
import azure.mgmt.network.models as network_models
import azure.mgmt.resource.resources.v2022_09_01
import azure.mgmt.resource.resources.v2022_09_01.models as models
import azure.mgmt.subscription
import jinja2
import jwt
import requests

REGION = "eastus2"
RUNNER_GROUP_ID = 10
GITHUB_ORGANIZATION = "canonical"
# This limit should not be exceeded during normal usage
# If a job is queued while this limit is exceeded, it will be skipped. A runner will *not* be
# provisioned later. (Later, if the limit is no longer exceeded, not enough runners will be
# provisioned to catch up with the jobs that were skipped.)
CONCURRENT_RUNNER_LIMIT = 400  # Keep in sync with `_30_DAY_BUDGET_CUTOFF_USD`
# Cost data is *not* real-time
# It is "typically available in Cost Management within 8-24 hours"
# https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/understand-cost-mgt-data#cost-and-usage-data-updates-and-retention
# To calculate monthly budget cutoff, take the actual budget and subtract
# `CONCURRENT_RUNNER_LIMIT` * price of runner per hour * 24 hours
# So that, if cost data is delayed by 24 hours, we do not exceed the actual budget
# Spot instance price can increase to standard price (to avoid eviction) since we set
# `"maxPrice": -1`—so use standard price to calculate budget cutoff
_30_DAY_BUDGET_CUTOFF_USD = (
    # 2500 - 400 * 0.1810 * 24
    760  # Keep in sync with Azure budget
)
assert _30_DAY_BUDGET_CUTOFF_USD < 2500 - CONCURRENT_RUNNER_LIMIT * 0.1810 * 24

# Set root logging level to WARNING (used by our Python package dependencies)
logging.getLogger().setLevel(logging.WARNING)
# Create INFO level logger for our logs
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
app = func.FunctionApp()


def get_credential():
    # Use function instead of global variable so that Azure detects app functions correctly even if
    # credential environment variables are missing. (For easier troubleshooting)

    # Managed identity adds ~8 seconds
    # GitHub webhooks have 10 second timeout
    # (https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#respond-within-10-seconds)
    # Use Azure Functions application settings (accessible as environment variables) instead of managed identity
    return azure.identity.EnvironmentCredential()


def get_client():
    return azure.mgmt.resource.resources.v2022_09_01.ResourceManagementClient(
        get_credential(), os.environ["AZURE_SUBSCRIPTION_ID"]
    )


def get_billing_last_30_days():
    now = datetime.datetime.now(datetime.UTC)
    old = now - datetime.timedelta(days=30)
    # From testing, it appears that Azure only uses the date, not the time
    # In case that behavior changes in the future, remove the time from `old`
    old = datetime.datetime(
        year=old.year, month=old.month, day=old.day, tzinfo=datetime.UTC
    )
    query = cost_models.QueryDefinition(
        type=cost_models.ExportType.ACTUAL_COST,
        timeframe=cost_models.TimeframeType.CUSTOM,
        time_period=cost_models.QueryTimePeriod(from_property=old, to=now),
        dataset=cost_models.QueryDataset(
            granularity=cost_models.GranularityType.DAILY,
            aggregation={
                # Key unused
                "CostUSD": cost_models.QueryAggregation(
                    name="CostUSD", function=cost_models.FunctionType.SUM
                )
            },
        ),
    )
    cost_client = azure.mgmt.costmanagement.CostManagementClient(get_credential())
    result = cost_client.query.usage(
        f'/subscriptions/{os.environ["AZURE_SUBSCRIPTION_ID"]}/', query
    )
    # API response is "columns" (header row) and "rows" (list of values; ordering matches "columns"
    # ordering)
    # Convert API response to list[dict]
    keys = [column.name for column in result.columns]
    return [dict(zip(keys, row)) for row in result.rows]


@app.schedule(
    schedule="49 * * * *",  # Every hour at :49
    arg_name="timer",
)
def billing_killswitch(timer: func.TimerRequest) -> None:
    """Cancel Azure subscription if `_30_DAY_BUDGET_CUTOFF_USD` exceeded"""
    days = get_billing_last_30_days()
    # Cost of previous 30 days + cost today
    cost = round(sum(day["CostUSD"] for day in days))
    if cost >= _30_DAY_BUDGET_CUTOFF_USD:
        # Cancel subscription
        subscription_client = azure.mgmt.subscription.SubscriptionClient(
            get_credential()
        )
        subscription_client.subscription.cancel(
            os.environ["AZURE_SUBSCRIPTION_ID"],
            # Undocumented API feature
            # (https://github.com/Azure/azure-rest-api-specs/issues/20254#issuecomment-1708620983)
            # Reverse-engineered from Azure Portal
            params={"IgnoreResourceCheck": True},
        )
    else:
        logger.info(f"30 day {cost=} under budget {_30_DAY_BUDGET_CUTOFF_USD}")


def response(body: str = None, *, status_code: int, log=True):
    if log:
        logger.info(f"Response {status_code=} {body=}")
    return func.HttpResponse(body, status_code=status_code)


@app.route(
    route="budget_exceeded",
    trigger_arg_name="request",
    auth_level=func.AuthLevel.FUNCTION,
    methods=(func.HttpMethod.POST,),
)
def budget_exceeded(request: func.HttpRequest) -> func.HttpResponse:
    """Cancel Azure subscription

    Triggered by Azure budget alert
    https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets#trigger-an-action-group
    """
    subscription_client = azure.mgmt.subscription.SubscriptionClient(get_credential())
    subscription_client.subscription.cancel(
        os.environ["AZURE_SUBSCRIPTION_ID"],
        # Undocumented API feature
        # (https://github.com/Azure/azure-rest-api-specs/issues/20254#issuecomment-1708620983)
        # Reverse-engineered from Azure Portal
        params={"IgnoreResourceCheck": True},
    )
    return response("Subscription cancelled", status_code=200)


@dataclasses.dataclass
class Day:
    cost_usd: float
    date: datetime.date

    @classmethod
    def from_azure_api(cls, api_data: dict):
        # Example: "20240621"
        date = str(api_data["UsageDate"])
        assert len(date) == 8
        date = datetime.date(
            year=int(date[0:4]), month=int(date[4:6]), day=int(date[6:8])
        )
        return cls(api_data["CostUSD"], date)


@app.schedule(
    schedule="0 6 * * *",  # Every day at 06:00 UTC
    arg_name="timer",
)
def billing_notification(timer: func.TimerRequest) -> None:
    """Send Mattermost message with billing usage"""
    days_ = [Day.from_azure_api(day) for day in get_billing_last_30_days()]
    today = datetime.date.today()

    def cost(previous_days: int):
        return round(
            sum(
                day.cost_usd
                for day in days_
                if (today - datetime.timedelta(days=previous_days)) <= day.date < today
            )
        )

    yesterday = cost(1)
    previous_7_days = cost(7)
    previous_30_days = cost(30)
    # https://docs.mattermost.com/collaborate/format-messages.html#tables
    message = f"""Time period | Cost
-|-:
Yesterday (UTC) | ${yesterday}
Previous 7 days | ${previous_7_days}
Previous 30 days | ${previous_30_days}
"""
    # Attempt to calculate savings. If that fails, send notification anyway
    try:
        now = datetime.datetime.now(datetime.UTC)
        query = cost_models.QueryDefinition(
            type=cost_models.ExportType.ACTUAL_COST,
            timeframe=cost_models.TimeframeType.CUSTOM,
            time_period=cost_models.QueryTimePeriod(
                from_property=datetime.datetime(
                    year=2024, month=6, day=1, tzinfo=datetime.UTC
                ),
                to=now,
            ),
            dataset=cost_models.QueryDataset(
                granularity=cost_models.GranularityType.DAILY,
                aggregation={
                    # Key unused
                    "CostUSD": cost_models.QueryAggregation(
                        name="CostUSD", function=cost_models.FunctionType.SUM
                    )
                },
            ),
        )
        cost_client = azure.mgmt.costmanagement.CostManagementClient(get_credential())
        result = cost_client.query.usage(
            f'/subscriptions/{os.environ["AZURE_SUBSCRIPTION_ID"]}/', query
        )
        if result.next_link:
            # TODO: support paginated API response
            raise NotImplementedError("Paginated response not supported")
        # API response is "columns" (header row) and "rows" (list of values; ordering matches "columns"
        # ordering)
        # Convert API response to Iterable[dict]
        keys = [column.name for column in result.columns]
        days = (dict(zip(keys, row)) for row in result.rows)

        all_time_cost = round(sum(day["CostUSD"] for day in days))

        query = cost_models.QueryDefinition(
            type=cost_models.ExportType.ACTUAL_COST,
            timeframe=cost_models.TimeframeType.CUSTOM,
            time_period=cost_models.QueryTimePeriod(
                from_property=datetime.datetime(
                    year=2024, month=6, day=1, tzinfo=datetime.UTC
                ),
                to=now,
            ),
            dataset=cost_models.QueryDataset(
                granularity=cost_models.GranularityType.DAILY,
                aggregation={
                    # Key unused
                    "UsageQuantity": cost_models.QueryAggregation(
                        name="UsageQuantity", function=cost_models.FunctionType.SUM
                    )
                },
                filter=cost_models.QueryFilter(
                    dimensions=cost_models.QueryComparisonExpression(
                        name="ResourceType",
                        operator=cost_models.QueryOperatorType.IN,
                        values=["Microsoft.Compute/virtualMachines"],
                    )
                ),
            ),
        )
        result = cost_client.query.usage(
            f'/subscriptions/{os.environ["AZURE_SUBSCRIPTION_ID"]}/', query
        )
        if result.next_link:
            # TODO: support paginated API response
            raise NotImplementedError("Paginated response not supported")
        # API response is "columns" (header row) and "rows" (list of values; ordering matches "columns"
        # ordering)
        # Convert API response to Iterable[dict]
        keys = [column.name for column in result.columns]
        days = (dict(zip(keys, row)) for row in result.rows)

        all_time_virtual_machine_hours = sum(day["UsageQuantity"] for day in days)
        # https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions#per-minute-rates-for-arm64-powered-larger-runners
        github_cost = all_time_virtual_machine_hours * 0.6
        cost_savings = round(github_cost - all_time_cost)
        message += f"\n\nThis automation has saved Canonical ${cost_savings} compared to GitHub-hosted runners"
    except Exception:
        logger.exception("Failed to display cost savings")
    response_ = requests.post(
        f'{os.environ["MATTERMOST_SERVER_URL"].removesuffix("/")}/api/v4/posts',
        headers={"Authorization": f'Bearer {os.environ["MATTERMOST_BOT_TOKEN"]}'},
        json={"channel_id": os.environ["MATTERMOST_CHANNEL_ID"], "message": message},
    )
    response_.raise_for_status()


@app.schedule(
    schedule="*/5 * * * *",  # Every 5 minutes
    arg_name="timer",
)
def cleanup(timer: func.TimerRequest) -> None:
    """Delete VMs that have been running for too long

    During normal usage, VMs will be deleted by GitHub webhook (after GitHub Actions job
    `timeout-minutes` exceeded
    https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes)

    This function exists in case
    - GitHub webhook doesn't get sent
    - GitHub Actions job doesn't have `timeout-minutes`
    - for redundancy, in case this script don't process GitHub webhook correctly (e.g. bug in code,
      expired secret)
    - for redundancy, in case a job isn't started on the VM and (our code on the) VM doesn't delete
      itself
    to protect against accidental cloud resource usage.
    """
    # Patch `ResourceGroup` to include `created_time` attribute
    # Based on `models.GenericResourceExpanded` source code
    # Uses undocumented API feature (https://stackoverflow.com/a/58830232)
    models.ResourceGroup._validation["created_time"] = {"readonly": True}
    models.ResourceGroup._attribute_map["created_time"] = {
        "key": "createdTime",
        "type": "iso-8601",
    }
    try:
        client = get_client()
        now = datetime.datetime.now(datetime.timezone.utc)
        for resource_group in client.resource_groups.list(
            filter="tagName eq 'runner'",
            # Needed to include `createdTime` in HTTP response from Azure API
            # Undocumented API feature (https://stackoverflow.com/a/58830232)
            params={"$expand": "createdTime"},
        ):
            delta = now - resource_group.created_time
            # Temporarily increased from 3 hours 45 minutes for
            # https://github.com/canonical/data-platform-workflows/pull/208
            past_long_timeout = delta > datetime.timedelta(hours=4, minutes=45)
            if past_long_timeout or (
                # Delete VMs that haven't started a job
                "job" not in (resource_group.tags or {})
                and delta > datetime.timedelta(minutes=10)
            ):
                try:
                    client.resource_groups.begin_delete(
                        resource_group.name,
                        force_deletion_types="Microsoft.Compute/virtualMachines",
                    )
                except azure.core.exceptions.ResourceNotFoundError:
                    # Resource group deletion might have started in an earlier execution
                    # (It is possible that the resource group, while in deletion, existed during
                    # `resource_groups.list()` but does not exist now.)
                    logger.info(
                        f"{resource_group.name=} already deleted. {past_long_timeout=}"
                    )
                else:
                    logger.info(f"Deleted {resource_group.name=}. {past_long_timeout=}")
    finally:
        # Undo patch
        # (Azure Functions seems to sometimes re-use Python processes.
        # Without this, sometimes the `job()` function fails to create a resource group.)
        models.ResourceGroup._validation.pop("created_time")
        models.ResourceGroup._attribute_map.pop("created_time")


class AzureKey(jwt.AbstractJWKBase):
    """Azure Key Vault key

    Use Azure Key Vault for signing (this script never has access to private key; private key never
    leaves Azure Key Vault)
    """

    def __init__(self, client: crypto.CryptographyClient) -> None:
        self._client = client

    def get_kty(self) -> str:
        return "RSA"

    def get_kid(self) -> str:
        raise NotImplementedError

    def is_sign_key(self) -> bool:
        return True

    def sign(self, message: bytes, **options) -> bytes:
        return self._client.sign(
            crypto.SignatureAlgorithm.rs256, hashlib.sha256(message).digest()
        ).signature

    def verify(self, *args, **kwargs):
        raise NotImplementedError

    def to_dict(self, *args, **kwargs):
        raise NotImplementedError

    @classmethod
    def from_dict(cls, *args, **kwargs):
        raise NotImplementedError


def provision_vm(
    *,
    client: azure.mgmt.resource.resources.v2022_09_01.ResourceManagementClient,
    request: func.HttpRequest,
    app_installation_id: int,
) -> func.HttpResponse:
    provisioned_runners = list(
        client.resource_groups.list(filter=f"tagName eq 'runner'")
    )
    if len(provisioned_runners) >= CONCURRENT_RUNNER_LIMIT:
        return response("Concurrent runner limit exceeded", status_code=290)
    # Authenticate as GitHub App installation
    # (https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
    payload = {
        # Issued at time
        "iat": int(time.time()),
        # JWT expiration time (10 minutes maximum)
        "exp": int(time.time()) + 60,
        # GitHub App's identifier
        "iss": int(os.environ["GITHUB_APP_ID"]),
    }
    key = AzureKey(
        crypto.CryptographyClient(
            f'{os.environ["KEY_VAULT_URI"]}keys/github-app', get_credential()
        )
    )
    github_jwt = jwt.JWT().encode(payload, key, alg="RS256")
    response_ = requests.post(
        f"https://api.github.com/app/installations/{app_installation_id}/access_tokens",
        json={"permissions": {"organization_self_hosted_runners": "write"}},
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {github_jwt}",
        },
    )
    response_.raise_for_status()
    token = response_.json()["token"]
    # Get latest available runner version for GitHub organization
    # "Note: Actions Runner follows a progressive release policy, so the latest release might not
    # be available to your enterprise, organization, or repository yet."
    # (from https://github.com/actions/runner/releases release notes)
    response_ = requests.get(
        f"https://api.github.com/orgs/{GITHUB_ORGANIZATION}/actions/runners/downloads",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
        },
    )
    response_.raise_for_status()
    downloads = [
        download
        for download in response_.json()
        if download["os"] == "linux" and download["architecture"] == "arm64"
    ]
    if len(downloads) != 1:
        raise ValueError("len(downloads) != 1")
    download = downloads[0]
    resource_group_name = f'runner-{request.headers["X-GitHub-Delivery"]}'
    response_ = requests.post(
        f"https://api.github.com/orgs/{GITHUB_ORGANIZATION}/actions/runners/generate-jitconfig",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
        },
        json={
            "name": resource_group_name,
            "runner_group_id": RUNNER_GROUP_ID,
            "labels": [
                "self-hosted",
                "data-platform",
                "ubuntu",
                "ARM64",
                "4cpu16ram",
            ],
        },
    )
    response_.raise_for_status()
    jit_config = response_.json()["encoded_jit_config"]
    # Provision VM
    resource_group = client.resource_groups.create_or_update(
        resource_group_name,
        models.ResourceGroup(
            location=REGION,
            tags={
                "runner": "",
                "runners": "",
                "team": "data-platform",
                "architecture": "ARM64",
                "size": "4cpu16ram",
            },
        ),
    )
    logger.info(f"Created {resource_group.name=}")
    with open("vm_template.json", "r") as file:
        vm_template = json.load(file)
    with open("cloud_init.sh.jinja", "r") as file:
        cloud_init_template = file.read()
    client.deployments.begin_create_or_update(
        resource_group.name,
        f"deployment-{resource_group_name}",
        models.Deployment(
            properties=models.DeploymentProperties(
                template=vm_template,
                parameters={
                    "delete_vm_custom_role_id": {
                        "value": os.environ["DELETE_VM_CUSTOM_ROLE_ID"]
                    },
                    "cloud_init": {
                        "value": jinja2.Template(
                            cloud_init_template,
                            autoescape=False,
                            undefined=jinja2.StrictUndefined,
                        ).render(
                            website_auth_client_id=os.environ["WEBSITE_AUTH_CLIENT_ID"],
                            website_hostname=os.environ["WEBSITE_HOSTNAME"],
                            resource_group_name=resource_group.name,
                            runner_download_url=download["download_url"],
                            runner_download_checksum=download["sha256_checksum"],
                            jit_config=jit_config,
                        ),
                    },
                },
                mode=models.DeploymentMode.COMPLETE,
            )
        ),
    )
    logger.info("Created virtual machine")
    return response("Runner provisioned", status_code=200)


class Action(str, enum.Enum):
    QUEUED = "queued"
    COMPLETED = "completed"


def no_operation(body: str):
    """HTTP response if webhook requires no operation

    (e.g. GitHub-hosted runner queued, `in_progress` webhook action)

    (and webhook successfully processed)
    """
    return response(
        body,
        status_code=240,  # Custom status code for easier monitoring from GitHub webhook logs
        log=False,  # Avoid ingestion costs on unnecessary logs
    )


def delete_dns_record(job_id: int):
    if custom_domain := os.environ.get("CUSTOM_DOMAIN_NAME"):
        # Delete DNS record (for convenient SSH)
        dns_client = azure.mgmt.dns.v2018_05_01.DnsManagementClient(
            get_credential(), os.environ["AZURE_SUBSCRIPTION_ID"]
        )
        dns_client.record_sets.delete(
            os.environ["CUSTOM_DOMAIN_RESOURCE_GROUP"],
            custom_domain,
            str(job_id),
            dns_models.RecordType.A,
        )
        logger.info("Deleted DNS record")


@app.route(
    route="job",
    trigger_arg_name="request",
    auth_level=func.AuthLevel.FUNCTION,
    methods=(func.HttpMethod.POST,),
)
def job(request: func.HttpRequest) -> func.HttpResponse:
    """Create/delete VM in response to GitHub webhook

    Triggered on `workflow_job` webhook
    https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_job
    """
    # Validate webhook signature
    # (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#python-example)
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        return response("X-Hub-Signature-256 missing", status_code=401)
    expected_signature = (
        "sha256="
        + hmac.new(
            key=os.environ["GITHUB_WEBHOOK_SECRET"].encode("utf-8"),
            msg=request.get_body(),
            digestmod=hashlib.sha256,
        ).hexdigest()
    )
    if not hmac.compare_digest(signature, expected_signature):
        return response("Signature does not match", status_code=401)
    if request.headers.get("X-GitHub-Event") != "workflow_job":
        return response("Invalid GitHub event", status_code=400)
    try:
        body = request.get_json()
    except ValueError:
        return response("No valid JSON data", status_code=400)
    if body.get("organization", {"login": None})["login"] != GITHUB_ORGANIZATION:
        logger.info("Unauthorized organization")
        return response(status_code=403)
    try:
        action = Action(body["action"])
    except ValueError as exception:
        return no_operation(str(exception))
    labels = body["workflow_job"]["labels"]
    for required_label in (
        "self-hosted",
        "data-platform",
        "ubuntu",
        "ARM64",
        "4cpu16ram",
    ):
        if required_label not in labels:
            return no_operation(f"{required_label=} missing from {labels=}")
    job_id = body["workflow_job"]["id"]
    repository_name = body["repository"]["full_name"]
    # Regular logs for beginning/end of function execution are disabled because of high volume of
    # webhooks that have no operation (to avoid ingestion costs on unnecessary logs)
    logger.info(f"Executing job function {job_id=} {repository_name=}")
    client = get_client()
    if action == Action.QUEUED:
        return provision_vm(
            client=client,
            request=request,
            app_installation_id=body["installation"]["id"],
        )
    elif action == Action.COMPLETED:
        # Delete resource group
        resource_groups = list(
            client.resource_groups.list(
                filter=f"tagName eq 'job' and tagValue eq '{job_id}'"
            )
        )
        if len(resource_groups) > 1:
            raise ValueError("Multiple VMs with same job")
        elif len(resource_groups) == 0:
            delete_dns_record(job_id)
            return response(
                "Resource group not found (probably already deleted)",
                status_code=231,  # Custom status code for easier monitoring from GitHub webhook logs
            )
        resource_group_name = resource_groups[0].name
        logger.info(f"Deleting {resource_group_name=}")
        try:
            client.resource_groups.begin_delete(
                resource_group_name,
                force_deletion_types="Microsoft.Compute/virtualMachines",
            )
        except azure.core.exceptions.ResourceNotFoundError:
            delete_dns_record(job_id)
            return response(
                "Resource group already deleted",
                status_code=232,  # Custom status code for easier monitoring from GitHub webhook logs
            )
        delete_dns_record(job_id)
        return response(
            "Resource group deleted",
            status_code=230,  # Custom status code for easier monitoring from GitHub webhook logs
        )


@app.route(
    route="tag",
    trigger_arg_name="request",
    auth_level=func.AuthLevel.ANONYMOUS,
    methods=(func.HttpMethod.POST,),
)
def tag(request: func.HttpRequest) -> func.HttpResponse:
    """Add job ID to resource group tag

    When a VM is created, we don't know what job the runner will pick up.

    (Currently, we create VMs on demand [i.e. create for a job] but it's possible that the runner
    picks up a different job that was queued first.)

    When a job completes, we need to know which VM to delete.


    Once a job is sent to the runner (once the job ID is available), we use a pre-job script to
    trigger this function.
    (https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/running-scripts-before-or-after-a-job)

    Note: The script (trusted code) runs before the job (untrusted code).

    This function can be run once per VM. (The resource group tag can only be set once.)

    Subsequent calls return 403 Forbidden. This prevents malicious code in the job from updating
    the resource group tag and preventing deletion of the VM.


    To ensure that this function is run once per VM, we need to authenticate the VM.
    This is accomplished with the Microsoft identity platform
    (https://learn.microsoft.com/en-us/entra/identity-platform/)
    and (system-assigned) managed identities (one per VM)
    (https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
    """
    unauthenticated = func.HttpResponse(status_code=401)
    try:
        client_principal = request.headers["x-ms-client-principal"]
    except KeyError as exception:
        logger.info(str(exception))
        return unauthenticated
    cp_claims = json.loads(base64.b64decode(client_principal).decode())["claims"]
    cp_audience = [claim["val"] for claim in cp_claims if claim["typ"] == "aud"]
    if (
        len(cp_audience) != 1
        or cp_audience[0] != f'https://{os.environ["WEBSITE_HOSTNAME"]}/'
    ):
        logger.info("Invalid client principal audience")
        return unauthenticated
    response_ = requests.get(
        f'https://{os.environ["WEBSITE_HOSTNAME"]}/.auth/me',
        headers={"X-ZUMO-AUTH": request.headers["x-zumo-auth"]},
    )
    response_.raise_for_status()
    data = response_.json()
    if not (isinstance(data, list) and len(data) == 1):
        raise ValueError("len(data) != 1. Potential issue with token store")
    claims = data[0]["user_claims"]
    required_claims = {
        "aud": None,
        "iss": None,
        "http://schemas.microsoft.com/identity/claims/identityprovider": None,
        "http://schemas.microsoft.com/identity/claims/tenantid": None,
        "http://schemas.microsoft.com/identity/claims/objectidentifier": None,
    }
    for claim in claims:
        typ = claim["typ"]
        if typ in required_claims:
            if required_claims[typ] is None:
                required_claims[typ] = claim["val"]
            else:
                raise ValueError("Multiple claims of same type")
    if required_claims["aud"] != f'api://{os.environ["WEBSITE_AUTH_CLIENT_ID"]}':
        logger.info("Invalid audience")
        return unauthenticated
    if (
        required_claims["iss"]
        != f'https://sts.windows.net/{os.environ["AZURE_TENANT_ID"]}/'
    ):
        logger.info("Invalid issuer")
        return unauthenticated
    if (
        required_claims["http://schemas.microsoft.com/identity/claims/identityprovider"]
        != f'https://sts.windows.net/{os.environ["AZURE_TENANT_ID"]}/'
    ):
        logger.info("Invalid identity provider")
        return unauthenticated
    if (
        required_claims["http://schemas.microsoft.com/identity/claims/tenantid"]
        != os.environ["AZURE_TENANT_ID"]
    ):
        logger.info("Invalid tenant ID")
        return unauthenticated
    vm_managed_identity_object_id = required_claims[
        "http://schemas.microsoft.com/identity/claims/objectidentifier"
    ]
    if not vm_managed_identity_object_id:
        logger.info("Missing VM ID")
        return unauthenticated

    request_data = request.get_json()
    try:
        resource_group_name = request_data["resource_group"]
        if not isinstance(resource_group_name, str):
            raise ValueError
        valid_characters = string.ascii_letters + string.digits + "-"
        for character in resource_group_name:
            if character not in valid_characters:
                raise ValueError
    except (KeyError, ValueError):
        return response("Invalid resource group name", status_code=400)
    client = get_client()
    try:
        vm = client.resources.get_by_id(
            f'/subscriptions/{os.environ["AZURE_SUBSCRIPTION_ID"]}/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/virtualMachines/runner',
            api_version="2021-04-01",
        )
    except azure.core.exceptions.ResourceNotFoundError:
        logger.info("VM not found for resource group")
        return response("VM not found for managed identity", status_code=403)
    if vm.identity.principal_id != vm_managed_identity_object_id:
        logger.info("VM ID does not match")
        return response("VM not found for managed identity", status_code=403)
    resource_group = client.resource_groups.get(resource_group_name)
    tags = resource_group.tags or {}
    if "runner" not in tags:
        logger.info("runner tag missing")
        return response("VM not found for managed identity", status_code=403)
    if "job" in tags:
        return response("job tag already added", status_code=403)
    try:
        job_id = request_data["job_id"]
        if not isinstance(job_id, int):
            raise ValueError
    except (KeyError, ValueError):
        return response("Invalid job id", status_code=400)
    try:
        repository = request_data["repository"]
        if not isinstance(repository, str) and re.fullmatch(
            r"[a-zA-Z0-9\-]+/[a-zA-Z0-9.\-_]+", repository
        ):
            raise ValueError
        repository = repository.removeprefix(f"{GITHUB_ORGANIZATION}/")
    except (KeyError, ValueError):
        return response("Invalid repository", status_code=400)
    try:
        event = request_data["event"]
        if not isinstance(event, str) and re.fullmatch(r"[a-z_]+", event):
            raise ValueError
    except (KeyError, ValueError):
        return response("Invalid event", status_code=400)
    try:
        github_username = request_data["github_username"]
        if not isinstance(github_username, str) and re.fullmatch(
            r"[a-zA-Z0-9\-]+", github_username
        ):
            raise ValueError
    except (KeyError, ValueError):
        return response("Invalid GitHub username", status_code=400)
    try:
        git_ref = request_data["git_ref"]
        if not isinstance(git_ref, str):
            raise ValueError
    except (KeyError, ValueError):
        return response("Invalid git ref", status_code=400)
    logger.info(f"Tagging {resource_group_name=} {job_id=} {repository=}")
    tags = {
        "job": str(job_id),
        "repository": repository,
        "event": event,
        "git_ref": git_ref,
    }
    if event != "schedule":
        # Username will be whoever modified schedule last, which is not helpful data
        # Omit username on `schedule` to avoid skewing data
        tags["github_username"] = github_username
    client.tags.begin_update_at_scope(
        resource_group.id,
        models.TagsPatchResource(
            operation=models.TagsPatchOperation.MERGE,
            properties=models.Tags(tags=tags),
        ),
    )
    if custom_domain := os.environ.get("CUSTOM_DOMAIN_NAME"):
        # Create DNS record for convenient SSH
        # For example, for job 26589009357, create DNS record at 26589009357.example.com so that
        # developer can SSH into runner with `ssh runner@26589009357.example.com`

        # Get runner's IP address
        network_client = azure.mgmt.network.NetworkManagementClient(
            get_credential(),
            os.environ["AZURE_SUBSCRIPTION_ID"],
            api_version="2023-09-01",
        )
        public_ip: network_models.PublicIPAddress = network_client.public_ip_addresses.get(
            resource_group_name=resource_group_name,
            public_ip_address_name="runner-public-ip",  # Copied from vm_template.json
        )
        # Create DNS record
        dns_client = azure.mgmt.dns.v2018_05_01.DnsManagementClient(
            get_credential(), os.environ["AZURE_SUBSCRIPTION_ID"]
        )
        dns_client.record_sets.create_or_update(
            os.environ["CUSTOM_DOMAIN_RESOURCE_GROUP"],
            custom_domain,
            str(job_id),
            dns_models.RecordType.A,
            dns_models.RecordSet(
                ttl=300,
                a_records=[
                    dns_models.ARecord(ipv4_address=public_ip.ip_address),
                ],
            ),
        )
        logger.info("Added DNS record")
    return response("job tag added", status_code=200)
