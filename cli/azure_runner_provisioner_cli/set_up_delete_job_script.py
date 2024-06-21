import argparse
import importlib.resources
import pathlib
import stat
import string

from . import templates


def main():
    """Copy script to delete VM if no job started after 5 minutes"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-group-name", required=True)
    args = parser.parse_args()
    template = (
        importlib.resources.files(templates)
        / "delete_if_no_job_after_5_minutes.sh.template"
    )
    rendered = string.Template(template.read_text(encoding="utf-8")).substitute(
        resource_group_name=args.resource_group_name
    )
    script = pathlib.Path.home() / template.name.removesuffix(".template")
    script.write_text(rendered, encoding="utf-8")
    # chmod +x
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
