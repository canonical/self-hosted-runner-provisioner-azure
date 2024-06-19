# How to monitor billing

## Emergency stop button
Cancel the Azure subscription
1. Go to https://portal.azure.com/#@canonical.com/resource/subscriptions/afee70ad-e2a4-4ea2-8663-68682ca2731a/overview
2. Click "Cancel subscription"
3. Reason for cancellation: `Other`
4. Click checkbox for "Turn off my resources. I understand that my subscription and data will be deleted."
5. Click "Cancel subscription"

For more detailed instructions, see https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/cancel-azure-subscription#cancel-a-subscription-in-the-azure-portal

### Backup method
Delete GitHub App private key
1. Go to https://github.com/organizations/canonical/settings/apps/data-platform-arm-runner
2. Scroll down to "Private keys"
3. Click "Generate a private key"
4. Delete the **old** private key

This will prevent any new runners from being provisioned. Existing runners will continue to run and will be cleaned up after their jobs complete.

Runners account for the vast majority of billing costs. However, other resources will not be cleaned up unless the Azure subscription is cancelled.

## View billing usage
> [!WARNING]
> Cost data is **not** real-time. It is "typically available in Cost Management within 8-24 hours". https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/understand-cost-mgt-data#cost-and-usage-data-updates-and-retention

The `CONCURRENT_RUNNER_LIMIT` in [function_app.py](../function_app.py) is used to control how quickly costs can increase.

View billing usage here: https://portal.azure.com/#@canonical.com/resource/subscriptions/afee70ad-e2a4-4ea2-8663-68682ca2731a/costByResource

Use tags to filter by things like GitHub repository, runner size, etc.

Azure billing documentation: https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/quick-acm-cost-analysis
