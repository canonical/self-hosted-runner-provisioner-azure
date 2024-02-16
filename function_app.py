import base64
import datetime
import enum
import json
import logging
import os
import time

import azure.core.exceptions
import azure.functions as func
import azure.identity
import azure.mgmt.resource.resources.v2022_09_01
import azure.mgmt.resource.resources.v2022_09_01.models as models
import requests

REGION = "eastus2"

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
    schedule="*/30 * * * *",  # Every 30 minutes
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
    client = get_client()
    now = datetime.datetime.now(datetime.timezone.utc)
    for resource_group in client.resource_groups.list(
        filter="tagName eq 'runner'",
        # Needed to include `createdTime` in HTTP response from Azure API
        # Undocumented API feature (https://stackoverflow.com/a/58830232)
        params={"$expand": "createdTime"},
    ):
        if now - resource_group.created_time > datetime.timedelta(hours=3, minutes=10):
            try:
                client.resource_groups.begin_delete(
                    resource_group.name,
                    force_deletion_types="Microsoft.Compute/virtualMachines",
                )
            except azure.core.exceptions.ResourceNotFoundError:
                # Resource group deletion might have started in an earlier execution
                # (It is possible that the resource group, while in deletion, existed during
                # `resource_groups.list()` but does not exist now.)
                logging.info(f"{resource_group.name} already deleted")
            else:
                logging.info(f"Deleted {resource_group.name=}")


class Action(str, enum.Enum):
    QUEUED = "queued"
    COMPLETED = "completed"


def response(body: str = None, *, status_code: int):
    logging.info(f"Response {status_code=} {body=}")
    return func.HttpResponse(body, status_code=status_code)


def no_runner(body: str):
    """HTTP response if no runner provisioned

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
    # TODO: validate https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
    if request.headers.get("X-GitHub-Event") != "workflow_job":
        return response("Invalid GitHub event", status_code=400)
    try:
        body = request.get_json()
    except ValueError:
        return response("No valid JSON data", status_code=400)
    try:
        action = Action(body["action"])
    except ValueError as exception:
        return no_runner(str(exception))
    labels = body["workflow_job"]["labels"]
    for required_label in (
        "self-hosted",
        "data-platform",
        "ubuntu",
        "ARM64",
        "4cpu16ram",
    ):
        if required_label not in labels:
            return no_runner(f"{required_label=} missing from {labels=}")
    job_id = body["workflow_job"]["id"]
    client = get_client()
    if action == Action.QUEUED:
        # Provision VM
        resource_group = client.resource_groups.create_or_update(
            f'test-runner-{request.headers["X-GitHub-Delivery"]}',
            models.ResourceGroup(location=REGION),
        )
        logging.info(f"Created {resource_group.name=}")
        with open("vm_template.json", "r") as file:
            template = json.load(file)
        client.deployments.begin_create_or_update(
            resource_group.name,
            f"test-deployment-job{job_id}",
            models.Deployment(
                # TODO: add runner tag
                properties=models.DeploymentProperties(
                    template=template,
                    parameters={
                        "location": {"value": REGION},
                        "networkInterfaceName1": {"value": "test-runner-1931_z1"},
                        "enableAcceleratedNetworking": {"value": True},
                        "networkSecurityGroupName": {"value": "test-runner-2-nsg"},
                        "networkSecurityGroupRules": {
                            "value": [
                                {
                                    "name": "SSH",
                                    "properties": {
                                        "priority": 300,
                                        "protocol": "TCP",
                                        "access": "Allow",
                                        "direction": "Inbound",
                                        "sourceAddressPrefix": "*",
                                        "sourcePortRange": "*",
                                        "destinationAddressPrefix": "*",
                                        "destinationPortRange": "22",
                                    },
                                }
                            ]
                        },
                        "subnetName": {"value": "default"},
                        "virtualNetworkName": {"value": "test-runner-2-vnet"},
                        "addressPrefixes": {"value": ["10.0.0.0/16"]},
                        "subnets": {
                            "value": [
                                {
                                    "name": "default",
                                    "properties": {"addressPrefix": "10.0.0.0/24"},
                                }
                            ]
                        },
                        "publicIpAddressName1": {"value": "test-runner-2-ip"},
                        "publicIpAddressType": {"value": "Static"},
                        "publicIpAddressSku": {"value": "Standard"},
                        "pipDeleteOption": {"value": "Delete"},
                        "virtualMachineName": {"value": "test-runner-2"},
                        "virtualMachineName1": {"value": "test-runner-2"},
                        "virtualMachineComputerName1": {"value": "test-runner-2"},
                        "virtualMachineRG": {"value": resource_group.name},
                        "osDiskType": {"value": "Standard_LRS"},
                        "ephemeralDiskType": {"value": "ResourceDisk"},
                        "osDiskDeleteOption": {"value": "Delete"},
                        "virtualMachineSize": {"value": "Standard_D4pds_v5"},
                        "nicDeleteOption": {"value": "Delete"},
                        "hibernationEnabled": {"value": False},
                        "adminUsername": {"value": "azureuser"},
                        "adminPublicKey": {
                            "value": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCL7VlyDLOrDrcEZoPej62PE65QaG5GLRRif+WpGdWEbuQLPmtSOekdFiHsZ16+FHsMuE+gWyVASXTWaU2uKe8F0Ef76wFsBZ8q9EkfVE3xwewmduV79POYpuYWdvVrA95JndQv3nNo8ntdjRUzPhN3YwGGbS35wnp3yf0sEJ+VGjvns7hrjh75jctA8lwrPGYlVfhuCWhxr8UMIXyVdFQ3CHd6fWXqWnHmcAG2FLbku0NKSmub5IYxNW/fh8qd+4g5ZD5jp7ejTidf7D6uSAtBbjv2xthGO2Mph+d8M7s7lhtMAlZDPoVJqmz58rk1cvHDaCID4+aK50ym287qb8+5VNzBycxxA3BmE3ukfdjHm6Rrp//M3/HcJBOEjkRaigXIJ2luj8d0iisG+6J00PHyPKyFHK0LWTVDZ5ib9kT11alpVIYqwHaiNoW/NkDvoHkF0hs+aM/A5xGRt6Y1znSqbgSjeI0mvwmd8VdO/aVZrYgW8cfCcVfNc0dSBI3JR6WDJFt0yUJxl05RYxHzMDtVEjmMbY2iUr+WfNBQdkh7kxD5K67DSMDvo130lJauNagz5VDUo3GVVfby0hXRWxG+1XP7DgeKtmR02ZwwMZxMC26F5Y6RMEObDC6YhJtqwV7cqovX105aDbZgtS3Ym/vKlcpfZhJgr9zljjplJxKfLQ== carlcsaposs@laptop"
                        },
                        "virtualMachine1Zone": {"value": "1"},
                    },
                    mode=models.DeploymentMode.COMPLETE,
                )
            ),
        )
        logging.info("Created virtual machine")
        return response("Runner provisioned", status_code=200)
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
        logging.info(str(exception))
        return unauthenticated
    cp_claims = json.loads(base64.b64decode(client_principal).decode())["claims"]
    cp_audience = [claim["val"] for claim in cp_claims if claim["typ"] == "aud"]
    if (
        len(cp_audience) != 1
        or cp_audience[0] != f'https://{os.environ["WEBSITE_HOSTNAME"]}/'
    ):
        logging.info("Invalid client principal audience")
        return unauthenticated
    for _ in range(15):
        response_ = requests.get(
            f'https://{os.environ["WEBSITE_HOSTNAME"]}/.auth/me',
            headers={"X-ZUMO-AUTH": request.headers["x-zumo-auth"]},
        )
        response_.raise_for_status()
        data = response_.json()
        if isinstance(data, list) and len(data) == 1:
            break
        elif isinstance(data, list) and len(data) > 1:
            raise ValueError("len(data) > 1")
        # Workaround for `/.auth/me` sometimes returning no data
        time.sleep(1)
        logging.info("Retrying /.auth/me")
    else:
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
        logging.info("Invalid audience")
        return unauthenticated
    if (
        required_claims["iss"]
        != f'https://sts.windows.net/{os.environ["AZURE_TENANT_ID"]}/'
    ):
        logging.info("Invalid issuer")
        return unauthenticated
    if (
        required_claims["http://schemas.microsoft.com/identity/claims/identityprovider"]
        != f'https://sts.windows.net/{os.environ["AZURE_TENANT_ID"]}/'
    ):
        logging.info("Invalid identity provider")
        return unauthenticated
    if (
        required_claims["http://schemas.microsoft.com/identity/claims/tenantid"]
        != os.environ["AZURE_TENANT_ID"]
    ):
        logging.info("Invalid tenant ID")
        return unauthenticated
    vm_managed_identity_object_id = required_claims[
        "http://schemas.microsoft.com/identity/claims/objectidentifier"
    ]
    if not vm_managed_identity_object_id:
        logging.info("Missing VM ID")
        return unauthenticated

    client = get_client()
    resources = client.resources.list(
        filter=f"identity/principalId eq '{vm_managed_identity_object_id}' and resourceType eq 'Microsoft.Compute/virtualMachines'"
    )
    iterator = iter(resources)
    try:
        resource = next(iterator)
    except StopIteration:
        logging.info("No VMs found with ID")
        return unauthenticated
    try:
        next(iterator)
    except StopIteration:
        pass
    else:
        raise ValueError("Multiple VMs found with ID")
    # Example: "/subscriptions/9b6fef27-c342-4e4d-b649-e94a7a9a4588/resourceGroups/runner-job21601933747/providers/Microsoft.Compute/virtualMachines/runner"
    id: str = resource.id
    prefix = f'/subscriptions/{os.environ["AZURE_SUBSCRIPTION_ID"]}/resourceGroups/'
    if not id.startswith(prefix):
        raise ValueError("Unrecognized resource ID format")
    id = id.removeprefix(prefix)
    if "/" not in id:
        raise ValueError("Unrecognized resource ID format")
    resource_group_name = id.split("/")[0]

    resource_group = client.resource_groups.get(resource_group_name)
    tags = resource_group.tags or {}
    if "runner" not in tags:
        logging.info("runner tag missing")
        return unauthenticated
    if "job" in tags:
        return response("job tag already added", status_code=403)
    try:
        job_id = request.get_json()["job_id"]
        if not isinstance(job_id, int):
            raise ValueError
    except (ValueError, KeyError):
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
