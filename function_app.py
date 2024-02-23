import base64
import datetime
import enum
import hashlib
import hmac
import json
import logging
import os
import string
import time

import azure.core.exceptions
import azure.functions as func
import azure.identity
import azure.keyvault.keys.crypto as crypto
import azure.mgmt.resource.resources.v2022_09_01
import azure.mgmt.resource.resources.v2022_09_01.models as models
import jwt
import requests

REGION = "eastus2"
RUNNER_GROUP_ID = 1
GITHUB_ORGANIZATION = "canonical-test2"
# This limit should not be exceeded during normal usage
# If a job is queued while this limit is exceeded, it will be skipped. A runner will *not* be
# provisioned later. (Later, if the limit is no longer exceeded, not enough runners will be
# provisioned to catch up with the jobs that were skipped.)
CONCURRENT_RUNNER_LIMIT = 50

# Set root logging level to WARNING (used by our Python package dependencies)
logging.getLogger().setLevel(logging.WARNING)
# Create INFO level logger for our logs
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
app = func.FunctionApp()


def get_client():
    # Use function instead of global variable so that Azure detects app functions correctly even if
    # credential environment variables are missing. (For easier troubleshooting)

    # Managed identity adds ~8 seconds
    # GitHub webhooks have 10 second timeout
    # (https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#respond-within-10-seconds)
    # Use Azure Functions application settings (accessible as environment variables) instead of managed identity
    credential = azure.identity.EnvironmentCredential()

    return azure.mgmt.resource.resources.v2022_09_01.ResourceManagementClient(
        credential, os.environ["AZURE_SUBSCRIPTION_ID"]
    )


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
            past_long_timeout = delta > datetime.timedelta(hours=3, minutes=10)
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


def response(body: str = None, *, status_code: int):
    logger.info(f"Response {status_code=} {body=}")
    return func.HttpResponse(body, status_code=status_code)


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
            f'{os.environ["KEY_VAULT_URI"]}keys/github-app',
            azure.identity.EnvironmentCredential(),
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
        template = json.load(file)
    client.deployments.begin_create_or_update(
        resource_group.name,
        f"deployment-{resource_group_name}",
        models.Deployment(
            properties=models.DeploymentProperties(
                template=template,
                parameters={
                    "delete_vm_custom_role_id": {
                        "value": os.environ["DELETE_VM_CUSTOM_ROLE_ID"]
                    },
                    "cloud_init": {
                        # TODO future improvement: use Jinja template
                        "value": f"""#!/bin/bash
set +e
runuser runner --login << 'EOF'
set -e
sudo apt-get update
# Install Azure CLI
# (https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt#option-2-step-by-step-installation-instructions)
sudo apt-get install ca-certificates curl apt-transport-https lsb-release gnupg -y
sudo mkdir -p /etc/apt/keyrings
curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/microsoft.gpg > /dev/null
sudo chmod go+r /etc/apt/keyrings/microsoft.gpg
AZ_DIST=$(lsb_release -cs)
echo "deb [arch=`dpkg --print-architecture` signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $AZ_DIST main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
sudo apt-get update
sudo apt-get install azure-cli -y

sudo apt-get install python3-pip python3-venv -y
python3 -m pip install pipx
python3 -m pipx ensurepath
sudo ln -s /usr/bin/python3 /usr/bin/python
EOF
if [[ $? == 0 ]]
then
    # Separate runuser to update path
    runuser runner --login << 'EOF'
    set -e
    pipx install git+https://github.com/canonical/self-hosted-runner-provisioner-azure#subdirectory=cli
    set-up-pre-job-script --website-auth-client-id '{os.environ["WEBSITE_AUTH_CLIENT_ID"]}' --website-hostname '{os.environ["WEBSITE_HOSTNAME"]}' --resource-group '{resource_group.name}'
    cd actions-runner
    curl -o actions-runner.tar.gz -L '{download["download_url"]}'
    echo '{download["sha256_checksum"]}  actions-runner.tar.gz' | shasum -a 256 -c
    tar xzf ./actions-runner.tar.gz
    ./run.sh --jitconfig '{jit_config}'
EOF
fi
# Delete VM regardless if previous commands fail
runuser runner --login << 'EOF'
set +e
az login --identity
az group delete --name '{resource_group.name}' --force-deletion-types Microsoft.Compute/virtualMachines --yes --no-wait
sudo shutdown now
EOF
"""
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
    )


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
    client = get_client()
    if action == Action.QUEUED:
        return provision_vm(
            client=client,
            request=request,
            app_installation_id=body["installation"]["id"],
        )
    elif action == Action.COMPLETED:
        # Delete resource group
        job_id = body["workflow_job"]["id"]
        resource_groups = list(
            client.resource_groups.list(
                filter=f"tagName eq 'job' and tagValue eq '{job_id}'"
            )
        )
        if len(resource_groups) > 1:
            raise ValueError("Multiple VMs with same job")
        elif len(resource_groups) == 0:
            return response(
                "Resource group not found (probably already deleted)",
                status_code=231,  # Custom status code for easier monitoring from GitHub webhook logs
            )
        try:
            client.resource_groups.begin_delete(
                resource_groups[0].name,
                force_deletion_types="Microsoft.Compute/virtualMachines",
            )
        except azure.core.exceptions.ResourceNotFoundError:
            return response(
                "Resource group already deleted",
                status_code=232,  # Custom status code for easier monitoring from GitHub webhook logs
            )
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
    client.tags.begin_update_at_scope(
        resource_group.id,
        models.TagsPatchResource(
            operation=models.TagsPatchOperation.MERGE,
            properties=models.Tags(tags={"job": str(job_id)}),
        ),
    )
    return response("job tag added", status_code=200)
    # TODO future improvement: create dns record (for convenient ssh)
