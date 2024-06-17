import argparse
import os
import pathlib
import re
import signal
import time

import requests


def get_step_pid(homedir: pathlib.Path):
    """Get process ID of currently running GitHub Actions step"""
    logs = list((homedir / "actions-runner/_diag").glob("Worker_*.log"))
    assert len(logs) == 1
    last_pid = None
    with logs[0].open("r") as file_:
        for line in file_:
            if match := re.search(
                # Log format from
                # https://github.com/actions/runner/blob/3f28dd845f5665426c4df81f2ef230d1cb1dd2da/src/Runner.Sdk/ProcessInvoker.cs#L338
                r"Process started with process id ([0-9]+), waiting for process exit\.",
                line,
            ):
                last_pid = match.group(1)
    assert last_pid
    return int(last_pid)


def write_to_step_stdout(step_pid: int, output: str, missing_ok=False):
    """Write to stdout of currently running GitHub Actions step"""
    try:
        with pathlib.Path(f"/proc/{step_pid}/fd/1").open("a") as file:
            file.write(output)
    except FileNotFoundError:
        if not missing_ok:
            raise


def handle_eviction(homedir: pathlib.Path):
    """Spot instance is getting evicted (in less than 30 seconds)

    https://learn.microsoft.com/en-us/azure/virtual-machines/spot-vms#eviction-policy
    """
    step_pid = get_step_pid(homedir)
    # Create annotation on GitHub Actions summary
    # (https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-notice-message)
    title = "Spot instance evicted"
    try:
        # Show job name in GitHub Actions annotation
        # We cannot access the job name directly, so check if the workflow (e.g.
        # data-platform-workflows integration_test_charm.yaml) saved the job name in a file
        job_name = (homedir / "dpw/job_name").read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        pass
    else:
        if "\n" not in job_name:
            title += f": {job_name}"
    write_to_step_stdout(
        step_pid,
        # Write notice once
        f"\n::notice title={title}::The runner's spot instance was evicted by Azure for capacity. Re-trigger this job\n\n",
    )
    # Gracefully stop currently running step
    # Re-implementation of `actions/runner` behavior when step is cancelled due to
    # `timeout-minutes`.
    # This is similar to, but different from `actions/runner` behavior when a job is cancelled (due
    # to `timeout-minutes` or cancellation of workflow run).
    # When a job is cancelled, the remaining steps do not run unless they use `if: ${{ always() }}`
    # or `if: ${{ cancelled() }}`.
    # (https://docs.github.com/en/actions/managing-workflow-runs/canceling-a-workflow#steps-github-takes-to-cancel-a-workflow-run)
    # When a step is cancelled due to `timeout-minutes`, the remaining steps can run if they use
    # `if: ${{ failure() }}` even if they do not use `always()` or `cancelled()`.

    # In both cases (job or step timeout), `actions/runner` sends a SIGINT, waits 7.5 seconds,
    # sends a SIGTERM, waits 2.5 seconds, and then sends a SIGKILL.
    # - The signals are sent to the step's process id and are not sent to child processes (e.g. in
    #   a step with `shell: bash` (default), the signal is sent to the bash process)
    # - `actions/runner` logs indicate that the SIGKILL is sent to the entire process tree (step's
    #   process & all children processes), but the source code seems to indicate that it is only
    #   sent to the step's process:
    #   https://github.com/actions/runner/issues/3341

    # Depending on the job, the desired behavior of this re-implementation could be different—to
    # match the step timeout or the job timeout.

    # For data-platform-workflows `integration_test_charm.yaml`, step timeout is preferred since,
    # most likely, eviction will happen during the long-running integration test step and we still
    # want to collect logs & Allure Report results in the remaining steps (that will hopefully
    # complete within 30 seconds before the VM is evicted).

    # For other jobs (e.g. with multiple long-running steps), it may be better to match the job
    # timeout behavior, so that steps (without `always()` or `cancelled()`) that have not started
    # do not run.

    # However, we don't have a choice & this re-implementation needs to match the behavior of
    # `actions/runner` during a step timeout.
    # (Because we are unable to send a cancellation event to `actions/runner` from the host
    # machine: https://github.com/orgs/community/discussions/128844)
    # If we were to send SIGTERM to `actions/runner`, the behavior would be even worse—the runner
    # stops almost immediately and `always()` & `cancelled()` steps and the post-job script do not
    # run. (Post-job script:
    # https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/running-scripts-before-or-after-a-job)

    # The behavior of `actions/runner`, as documented above, was confirmed by looking at
    # self-hosted runner logs (runner v2.317.0) and using
    # https://github.com/ringerc/github-actions-signal-handling-demo for GitHub-hosted
    # `ubuntu-latest` runners (also v2.317.0).
    os.kill(step_pid, signal.SIGINT)
    time.sleep(7.5)
    try:
        write_to_step_stdout(
            step_pid,
            # Write message again (without notice annotation) so that it appears at bottom of step logs
            "\nThe runner's spot instance was evicted by Azure for capacity. Re-trigger this job\n\n",
            missing_ok=True,
        )
        os.kill(step_pid, signal.SIGTERM)
        time.sleep(2.5)
        write_to_step_stdout(
            step_pid,
            # Write message again (without notice annotation) so that it appears at bottom of step logs
            "\nThe runner's spot instance was evicted by Azure for capacity. Re-trigger this job\n\n",
            missing_ok=True,
        )
        os.kill(step_pid, signal.SIGKILL)
    except ProcessLookupError:
        # Process already exited
        pass


def main():
    """Gracefully stop current GitHub Actions step during Azure spot instance eviction"""
    parser = argparse.ArgumentParser()
    # This script will run as root (in systemd service), so we can't use `~`
    parser.add_argument("--homedir", required=True)
    args = parser.parse_args()
    homedir = pathlib.Path(args.homedir)
    while True:
        response = requests.get(
            # https://learn.microsoft.com/en-us/azure/virtual-machines/linux/scheduled-events
            "http://169.254.169.254/metadata/scheduledevents",
            headers={"Metadata": "true"},
            params={"api-version": "2020-07-01"},
        )
        response.raise_for_status()
        for event in response.json()["Events"]:
            if event["EventType"] != "Preempt":
                continue
            handle_eviction(homedir)
            exit()
        time.sleep(1)
