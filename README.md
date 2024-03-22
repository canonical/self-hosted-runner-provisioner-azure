# self-hosted-runner-provisioner-azure

Provision just-in-time self-hosted GitHub Actions runners on Azure.

When a GitHub Actions job is queued, GitHub sends a [workflow_job](https://docs.github.com/en/webhooks/webhook-events-and-payloads?actionType=queued#workflow_job) webhook to Azure Functions, which executes `job()` in [function_app.py](function_app.py).

`job()` provisions a virtual machine on Azure.

## Features
- About 50x cheaper than GitHub-hosted runners

  Price per hour as of 2024-03:

   | Runner                                                                                                                                | [GitHub](https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions#per-minute-rates) | Azure Spot VM (eastus2) | Azure VM (eastus2) |
   |---------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|-------------------------|--------------------|
   | Standard X64 runner ([Standard_D4ads_v5](https://learn.microsoft.com/en-us/azure/virtual-machines/dasv5-dadsv5-series#dadsv5-series)) | $0.96                                                                                                                              | $0.0206                 | $0.2060            |
   | ARM64 runner ([Standard_D4pds_v5](https://learn.microsoft.com/en-us/azure/virtual-machines/dpsv5-dpdsv5-series#dpdsv5-series))        | $0.96                                                                                                                              | $0.0181                 | $0.1810            |

- Supports custom images—reduce execution time by pre-installing tools or pre-deploying test environment
- Full SSH access at any time (for authorized keys of your choice)
- Use any VM type/size available on Azure

## How to deploy

### Azure
1. Create Subscription
    - Name: `Self-hosted GitHub runners`
1. Create Function App
    - Resource group (create new): `runner-provisioner`
    - Name: `runner-provisioner`
    - Code or container: Code
    - Runtime stack: Python
    - Version: 3.11
    - Region: East US 2
    - Hosting plan: Consumption (Serverless)
    - Monitoring: Enable application insights
1. Create Key Vault
    - Resource group: `runner-provisioner`
    - Name: `runner-provisioner-vault`
    - Region: East US 2
1. Create Storage account
    - Resource group: `runner-provisioner`
    - Name: `runnerprovisionertoken`
    - Redundancy: Locally-redundant storage
    - Data Protection: Disable all soft delete options
1. Storage account -> Containers -> Create
    - (https://learn.microsoft.com/en-us/archive/blogs/jpsanders/azure-app-service-authentication-using-a-blob-storage-for-token-cache)
    - Name: `tokens`
1. Storage account -> Containers -> `tokens` -> Shared access tokens
    - Note: Create the shared access token on the container, not the storage account
    - Permissions: Read, Write, List
    - Expiry: 2 years in future **(set reminder)**
    - Generate
    - Copy SAS URL & paste into Function App configuration application setting `WEBSITE_AUTH_TOKEN_CONTAINER_SASURL`
1. Storage account -> Lifecycle management -> Add a rule
    - Name: `delete`
    - Apply to all blobs
    - Blob type: Block blobs
    - Blob subtype: Base blobs
    - If:
        - Created
        - More than `1` day ago
    - Then:
        - Delete the blob
1. Subscription -> Access control -> Add custom role
    - Name: `Delete VM`
    - Start from scratch
    - Add permission: `Microsoft.Resources/subscriptions/resourceGroups/delete`
    - Copy ID from JSON (after "roleDefinitions/")
    - Paste ID into Function App configuration `DELETE_VM_CUSTOM_ROLE_ID`
1. Subscription -> Access control -> Add custom role
    - Name: `Sign with key`
    - Start from scratch
    - Add permission: `Microsoft.KeyVault/vaults/keys/sign/action`
1. Subscription -> Access control -> Add custom role
    - Name: `Runner provisioner`
    - Start from scratch
    - Add permissions:
        ```
        Microsoft.Resources/subscriptions/resourceGroups/read
        Microsoft.Resources/subscriptions/resourceGroups/write
        Microsoft.Resources/subscriptions/resourceGroups/delete
        Microsoft.Resources/tags/write
        Microsoft.Resources/deployments/write
        Microsoft.Network/publicIPAddresses/read
        Microsoft.Network/publicIPAddresses/write
        Microsoft.Network/publicIPAddresses/join/action
        Microsoft.Network/networkSecurityGroups/read
        Microsoft.Network/networkSecurityGroups/write
        Microsoft.Network/networkSecurityGroups/join/action
        Microsoft.Network/virtualNetworks/read
        Microsoft.Network/virtualNetworks/write
        Microsoft.Network/virtualNetworks/subnets/join/action
        Microsoft.Network/networkInterfaces/write
        Microsoft.Network/networkInterfaces/join/action
        Microsoft.Compute/virtualMachines/read
        Microsoft.Compute/virtualMachines/write
        Microsoft.Authorization/roleAssignments/write
        ```
1. Microsoft Entra ID -> App registrations -> New registration
    - Name: `self-hosted-github-runner-provisioner`
    - Certificates & secrets -> New client secret
        - Description: `Runner provisioner`
        - Expires: 730 days **(set reminder)**
        - Copy value
    - Paste client secret into Function App configuration `AZURE_CLIENT_SECRET`
    - Go to overview, copy client ID & paste into Function App configuration `AZURE_CLIENT_ID`
    - Copy tenant ID & paste into Function App configuration `AZURE_TENANT_ID`
1. Subscription
    - Copy ID & paste into Function App configuration `AZURE_SUBSCRIPTION_ID`
1. Subscription -> Access control -> Add role assignment
    - Name: `Runner provisioner`
    - Members: `self-hosted-github-runner-provisioner`
    - Conditions:
        - Allow user to only assign selected roles to selected principals
        - Add action: Create or update role assignments
        - Add expression
            - Attribute source: Request
            - Attribute: Role definition ID
            - Operator: GuidEquals
            - Role: `Delete VM`
        - AND
        - Add expression
            - Attribute source: Request
            - Attribute: Principal type
            - Operator: StringEqualsIgnoreCase
            - Value: ServicePrincipal
1. Function App -> Authentication -> Add identity provider
    - Microsoft
    - Create new app registration
        - Name: `self-hosted-github-runner-provisioner-auth-provider`
    - Client application requirement: Allow requests from any application
    - Restrict access: Allow unauthenticated access
    - Token store: Enabled
1. Edit identity provider
    - Remove `/v2.0` from end of issuer URL
    - Tenant requirement: Allow requests from specific tenants
        - Copy `AZURE_TENANT_ID` from Function App configuration
1. Key Vault
    - Copy vault URI and paste into Function App configuration `KEY_VAULT_URI`
1. Key Vault -> Access control -> Add role assignment
    - Name: `Sign with key`
    - Members: `self-hosted-github-runner-provisioner`
1. Key Vault -> Access control -> Add role assignment
    - Name: `Key Vault Administrator`
    - Members: You
1. Generate throwaway SSH key
    - (Required by Azure to disable password authentication)
    - `ssh-keygen -t rsa -b 4096`
    - Paste public key into [vm_template.json](vm_template.json)
    - Securely delete private key
1. Follow step 1 in [GitHub instructions below](#github)
1. Deploy Function App
    - Clone this repository
    - Open repository in VS Code
    - Deploy to Azure: https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-vs-code-python?pivots=python-mode-decorators#deploy-the-project-to-azure
1. Subscription -> Resource providers
    - (https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-register-resource-provider?tabs=azure-portal#solution)
    - Register:
        ```
        Microsoft.Network
        Microsoft.Compute
        ```

### GitHub
1. (Optional) Create runner group: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups#creating-a-self-hosted-runner-group-for-an-organization. Change `RUNNER_GROUP_ID` in [function_app.py](function_app.py)
1. Register GitHub App under organization (https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)
    - Name: `Self-hosted runner provisioner`
    - Webhook URL: Go to Azure -> Function App -> `job` -> Get function URL -> default (function key)
    - Webhook secret:
        - Run
            ```python
            import secrets
            secrets.token_urlsafe()
            ```
        - Paste into GitHub
        - Paste into Azure Function App configuration `GITHUB_WEBHOOK_SECRET`
    - Permissions:
        - Repository -> Actions: Read-only
        - Organization -> Self-hosted runners: Read and write
    - Subscribe to events: Workflow job
    - Only allow installation on organization account
1. After registration
    - Copy app ID to Azure Function App configuration `GITHUB_APP_ID`
    - Generate a private key
    - Azure -> Key Vault -> Keys -> Generate/import
        - Import
        - Name: `github-app`
    - Delete private key file from local computer
    - Install App
