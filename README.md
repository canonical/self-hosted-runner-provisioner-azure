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

## Documentation
Documentation in [docs directory](docs)
