from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from safe_ssh_setup.models import DistroFamily


@dataclass
class DistroInfo:
    family: DistroFamily
    name: str
    version: str
    package_manager: str
    firewall: str
    auto_updates_package: str
    ssh_service: str


def detect_distro() -> DistroInfo:
    """Detect the Linux distribution from /etc/os-release."""
    os_release = {}
    path = Path("/etc/os-release")
    if not path.exists():
        raise DistroDetectionError("Cannot find /etc/os-release")

    for line in path.read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            os_release[key] = value.strip('"')

    name = os_release.get("NAME", "")
    version = os_release.get("VERSION_ID", "")
    id_like = os_release.get("ID_LIKE", "")
    distro_id = os_release.get("ID", "")

    identifiers = f"{distro_id} {id_like}".lower()

    if any(d in identifiers for d in ("debian", "ubuntu")):
        return DistroInfo(
            family=DistroFamily.DEBIAN,
            name=name,
            version=version,
            package_manager="apt",
            firewall="ufw",
            auto_updates_package="unattended-upgrades",
            ssh_service="ssh",
        )
    elif any(d in identifiers for d in ("fedora", "rhel", "centos", "rocky", "alma")):
        return DistroInfo(
            family=DistroFamily.RHEL,
            name=name,
            version=version,
            package_manager="dnf",
            firewall="firewalld",
            auto_updates_package="dnf-automatic",
            ssh_service="sshd",
        )
    else:
        raise DistroDetectionError(
            f"Unsupported distribution: {name}. "
            "Only Debian/Ubuntu and Fedora/RHEL are supported."
        )


class DistroDetectionError(Exception):
    pass


class PackageManager:
    """Abstraction over apt and dnf."""

    def __init__(self, distro: DistroInfo) -> None:
        self.distro = distro

    def install_command(self, packages: list[str]) -> str:
        pkgs = " ".join(packages)
        if self.distro.package_manager == "apt":
            return f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}"
        return f"dnf install -y {pkgs}"

    def update_command(self) -> str:
        if self.distro.package_manager == "apt":
            return "apt-get update -y"
        return "dnf check-update || true"


class FirewallAdapter:
    """Abstraction over ufw and firewalld."""

    def __init__(self, distro: DistroInfo) -> None:
        self.distro = distro

    def install_packages(self) -> list[str]:
        if self.distro.firewall == "ufw":
            return ["ufw"]
        return ["firewalld"]

    def allow_port_commands(self, port: int) -> list[str]:
        if self.distro.firewall == "ufw":
            return [f"ufw allow {port}/tcp"]
        return [
            f"firewall-cmd --permanent --add-port={port}/tcp",
            "firewall-cmd --reload",
        ]

    def rate_limit_commands(self, port: int) -> list[str]:
        if self.distro.firewall == "ufw":
            return [f"ufw limit {port}/tcp"]
        return [
            f"firewall-cmd --permanent --add-rich-rule="
            f"'rule family=ipv4 port port={port} protocol=tcp "
            f"accept limit value=10/m'",
            "firewall-cmd --reload",
        ]

    def default_deny_command(self) -> list[str]:
        if self.distro.firewall == "ufw":
            return ["ufw default deny incoming"]
        return [
            "firewall-cmd --permanent --set-default-zone=drop",
            "firewall-cmd --reload",
        ]

    def enable_commands(self) -> list[str]:
        if self.distro.firewall == "ufw":
            return ["ufw --force enable"]
        return [
            "systemctl enable --now firewalld",
        ]

    def remove_ssh_default_commands(self) -> list[str]:
        """Remove the default SSH service if using a non-standard port."""
        if self.distro.firewall == "ufw":
            return ["ufw delete allow OpenSSH 2>/dev/null || true"]
        return [
            "firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true",
            "firewall-cmd --reload",
        ]
