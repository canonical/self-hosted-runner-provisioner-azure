import importlib.resources
import pathlib
import string
import subprocess

from . import templates


def main():
    """Set up systemd service to listen to Azure spot instance eviction events"""
    template = (
        importlib.resources.files(templates) / "spot-eviction-listener.service.template"
    )
    rendered = string.Template(template.read_text(encoding="utf-8")).substitute(
        homedir=pathlib.Path.home()
    )
    service = pathlib.Path("/etc/systemd/system") / template.name.removesuffix(
        ".template"
    )
    temp_file = pathlib.Path(service.name)
    temp_file.write_text(rendered, encoding="utf-8")
    subprocess.run(["sudo", "mv", temp_file, service], check=True)
    subprocess.run(["sudo", "systemctl", "enable", "--now", service.name], check=True)
