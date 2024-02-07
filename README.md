# self-hosted-runner-provisioner-azure

Provision just-in-time self-hosted GitHub Actions runners on Azure.

When a GitHub Actions job is queued, GitHub sends a [workflow_job](https://docs.github.com/en/webhooks/webhook-events-and-payloads?actionType=queued#workflow_job) webhook to Azure Functions, which executes `job_queued` in [function_app.py](function_app.py).

`job_queued` provisions a virtual machine on Azure.
