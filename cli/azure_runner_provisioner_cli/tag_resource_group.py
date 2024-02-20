import argparse
import os

import azure.identity
import requests


def main():
    """Add job ID to resource group tag

    See `tag()` in `function_app.py`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--website-auth-client-id", required=True)
    parser.add_argument("--website-hostname", required=True)
    args = parser.parse_args()
    job_id = int(os.environ["GITHUB_JOB"])
    token1 = (
        azure.identity.ManagedIdentityCredential()
        .get_token(f"api://{args.website_auth_client_id}")
        .token
    )
    response = requests.post(
        f"https://{args.website_hostname}/.auth/login/aad",
        json={"access_token": token1},
    )
    response.raise_for_status()
    token2 = response.json()["authenticationToken"]
    response = requests.post(
        f"https://{args.website_hostname}/api/tag",
        headers={"X-ZUMO-AUTH": token2},
        json={"job_id": job_id},
    )
    response.raise_for_status()
