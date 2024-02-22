import argparse
import os
import pathlib
import re

import azure.identity
import requests


def get_jobs():
    """Get jobs & handle paginated response"""
    link = f'{os.environ["GITHUB_API_URL"]}/repos/{os.environ["GITHUB_REPOSITORY"]}/actions/runs/{os.environ["GITHUB_RUN_ID"]}/attempts/{os.environ["GITHUB_RUN_ATTEMPT"]}/jobs'
    while True:
        if not link:
            return
        response = requests.get(
            link,
            params={
                # Reduce number of API requests
                # (Rate limit: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#usage-limits)
                "per_page": 100
            },
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        for job in response.json()["jobs"]:
            yield job
        link = response.links.get("next", {"url": None})["url"]


def main():
    """Add job ID to resource group tag

    See `tag()` in `function_app.py`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--website-auth-client-id", required=True)
    parser.add_argument("--website-hostname", required=True)
    args = parser.parse_args()
    # Read job name from runner logs
    paths = list(
        pathlib.Path("~/actions-runner/_diag").expanduser().glob("Runner_*.log")
    )
    assert len(paths) == 1
    log = paths[0].read_text(encoding="utf-8")
    # Example log line with job name:
    # "[2024-02-20 10:28:21Z INFO Terminal] WRITE LINE: 2024-02-20 10:28:21Z: Running job: foo (1)"
    match = re.search("Running job: (.*?)\n", log)
    assert match
    # Example: "foo (1)"
    job_name = match.group(1)
    # Get job ID from GitHub API
    for job in get_jobs():
        if job["name"] == job_name:
            job_id = job["id"]
            break
    else:
        raise ValueError("Unable to find job ID")
    # Call `tag()` in `function_app.py`
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
