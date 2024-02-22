import argparse
import pathlib
import stat


def main():
    """Set up pre-job script to tag VM with job ID

    https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/running-scripts-before-or-after-a-job
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--website-auth-client-id", required=True)
    parser.add_argument("--website-hostname", required=True)
    args = parser.parse_args()
    script = pathlib.Path("~/tag_resource_group.sh").expanduser()
    script.write_text(
        f"""#!/bin/bash
tag-resource-group --website-auth-client-id '{args.website_auth_client_id}' --website-hostname '{args.website_hostname}'
""",
        encoding="utf-8",
    )
    # chmod +x
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    env_file = pathlib.Path("~/actions-runner/.env").expanduser()
    env_file.parent.mkdir()
    env_file.write_text(f"ACTIONS_RUNNER_HOOK_JOB_STARTED={script}", encoding="utf-8")
