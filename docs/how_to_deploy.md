# How to deploy

## Azure
1. Create Subscription
    - Name: `Self-hosted GitHub runners`
1. Enable tag inheritance for subscription: https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/enable-tag-inheritance#to-enable-tag-inheritance-in-the-azure-portal-for-a-subscription
1. Create Function App
    - Hosting plan: Consumption (Serverless)
    - Resource group (create new): `runner-provisioner`
    - Name: `runner-provisioner`
    - Code or container: Code
    - Runtime stack: Python
    - Version: 3.11
    - Region: East US 2
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
    - Copy SAS URL & paste into Function App environment variable (app settings) `WEBSITE_AUTH_TOKEN_CONTAINER_SASURL`
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
    - Paste ID into Function App environment variable `DELETE_VM_CUSTOM_ROLE_ID`
1. Subscription -> Access control -> Add custom role
    - Name: `Sign with key`
    - Start from scratch
    - Add permission: `Microsoft.KeyVault/vaults/keys/sign/action`
1. Microsoft Entra ID -> App registrations -> New registration
    - Name: `self-hosted-github-runner-provisioner`
    - Certificates & secrets -> New client secret
        - Description: `Runner provisioner`
        - Expires: 730 days **(set reminder)**
        - Copy value
    - Paste client secret into Function App environment variable `AZURE_CLIENT_SECRET`
    - Go to overview, copy client ID & paste into Function App environment variable `AZURE_CLIENT_ID`
    - Copy tenant ID & paste into Function App environment variable `AZURE_TENANT_ID`
1. Subscription
    - Copy ID & paste into Function App environment variable `AZURE_SUBSCRIPTION_ID`
1. Subscription -> Access control -> Add role assignment
    - Name: `Owner`
        - Owner role required to cancel subscription
    - Members: People on your team who will monitor billing & will shutdown the automation if needed
    - Conditions:
        - Allow user to assign all roles (highly privileged)
            - This is required to be able to cancel subscription
1. Subscription -> Access control -> Add role assignment
    - Name: `Billing Reader`
    - Members: People on your team who will monitor billing
      - Important: include people who were assigned the previous role
1. Subscription -> Access control -> Add role assignment
    - Name: `Owner`
        - Owner role required for billing killswitch that cancels subscription if budget exceeded
    - Members: `self-hosted-github-runner-provisioner`
    - Conditions:
        - Allow user to assign all roles (highly privileged)
            - This is required to be able to cancel subscription
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
        - Copy `AZURE_TENANT_ID` from Function App environment variable
1. Key Vault
    - Copy vault URI and paste into Function App environment variable `KEY_VAULT_URI`
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
1. Monitor -> Alerts -> Action groups -> Create
    - Resource group: `runner-provisioner`
    - Region: Global
    - Action group name: `budget-killswitch`
    - Display name: `Killswitch`
    - Actions
      - Action type: `Azure Function`
      - Name: `cancel-subscription`
      - Resource group: `runner-provisioner`
      - Function app: `runner-provisioner`
      - Azure Function: `budget_exceeded`
1. Subscription -> Budgets -> Add
    - Name: `runner-budget`
    - Reset period: `Monthly`
    - Expiration date: As far into future as possible **(set reminder)**
    - Amount: Keep in sync with `_30_DAY_BUDGET_CUTOFF_USD` in [function_app.py](../function_app.py)
    - Create alert
        - Type: Actual
        - %: 90
        - Action group: None
    - Create alert
        - Type: Actual
        - %: 100
        - Action group: `budget-killswitch`
    - Add alert recipients
        - Emails of people on your team who will monitor billing & will shutdown the automation if needed
1. Subscription -> Resource providers
    - (https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-register-resource-provider?tabs=azure-portal#solution)
    - Register:
        ```
        Microsoft.Network
        Microsoft.Compute
        ```
1. (Optional) Function App -> Custom domains -> Buy App Service domain
    - Resource group: `runner-provisioner`
    - Hostname assignment
        - root: No
        - 'www' subdomain: No
    - Auto renewal: Enable
    - Privacy protection: Enable
    - Paste domain name (e.g. example.com) into Function App environment variable `CUSTOM_DOMAIN_NAME`
    - Paste `runner-provisioner` into Function App environment variable `CUSTOM_DOMAIN_RESOURCE_GROUP`
1. (Only if previous step followed) DNS zones -> example.com -> Locks -> Delete lock
    - Needed to delete DNS records

## GitHub
1. (Optional) Create runner group: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups#creating-a-self-hosted-runner-group-for-an-organization. Change `RUNNER_GROUP_ID` in [function_app.py](../function_app.py)
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
        - Paste into Azure Function App environment variable `GITHUB_WEBHOOK_SECRET`
    - Permissions:
        - Repository -> Actions: Read-only
        - Organization -> Self-hosted runners: Read and write
    - Subscribe to events: Workflow job
    - Only allow installation on organization account
1. After registration
    - Copy app ID to Azure Function App environment variable `GITHUB_APP_ID`
    - Generate a private key
    - Azure -> Key Vault -> Keys -> Generate/import
        - Import
        - Name: `github-app`
    - Delete private key file from local computer
    - Install App

## Mattermost
1. Create bot account
    - https://developers.mattermost.com/integrate/reference/bot-accounts/
    - Paste token into Azure Function App environment variable `MATTERMOST_BOT_TOKEN`
    - Copy server URL (e.g. https://chat.charmhub.io) to Azure Function App environment variable `MATTERMOST_SERVER_URL`
1. Invite bot to channel
    - Copy channel ID (from info sidebar) to Azure Function App environment variable `MATTERMOST_CHANNEL_ID`
