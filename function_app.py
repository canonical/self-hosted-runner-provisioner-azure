import datetime
import enum
import json
import logging
import os

import azure.core.exceptions
import azure.functions as func
import azure.identity
import azure.mgmt.resource.resources.v2022_09_01
import azure.mgmt.resource.resources.v2022_09_01.models as models

REGION = "eastus2"

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


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
            client.resource_groups.begin_delete(
                resource_group.name,
                force_deletion_types="Microsoft.Compute/virtualMachines",
            )
            logging.info(f"Deleted {resource_group.name=}")


class Action(str, enum.Enum):
    QUEUED = "queued"
    COMPLETED = "completed"


def response(body: str, status_code: int):
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


@app.route(route="job", trigger_arg_name="request")
def job(request: func.HttpRequest) -> func.HttpResponse:
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
    resource_group_name = f"test-runner-job{job_id}"
    client = get_client()
    if action == Action.QUEUED:
        # Provision VM
        resource_group = client.resource_groups.create_or_update(
            resource_group_name, models.ResourceGroup(location=REGION)
        )
        logging.info(f"Created {resource_group_name=}")
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
        try:
            client.resource_groups.begin_delete(
                resource_group_name,
                force_deletion_types="Microsoft.Compute/virtualMachines",
            )
        except azure.core.exceptions.ResourceNotFoundError:
            return response(
                "Resource group already deleted",
                status_code=231,  # Custom status code for easier monitoring from GitHub webhook logs
            )
        return response(
            "Resource group deleted",
            status_code=230,  # Custom status code for easier monitoring from GitHub webhook logs
        )
