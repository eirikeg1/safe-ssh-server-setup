from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from safe_ssh_setup.models import DistroFamily
from safe_ssh_setup.system import default_interface

# Package names differ between families. Fedora/RHEL ship knockd inside
# "knock-server"; installing "knockd" there fails outright.
PACKAGE_ALIASES: dict[str, dict[str, str]] = {
    "knockd": {"apt": "knockd", "dnf": "knock-server"},
    "selinux-tools": {"apt": "", "dnf": "policycoreutils-python-utils"},
    "cron": {"apt": "cron", "dnf": "cronie"},
}


@dataclass
class CommandStep:
    """One argv command with the metadata the executor needs."""

    description: str
    argv: list[str]
    ignore_failure: bool = False
    ok_returncodes: tuple[int, ...] = (0,)


@dataclass
class DistroInfo:
    family: DistroFamily
    name: str
    version: str
    package_manager: str
    firewall: str
    auto_updates_package: str
    ssh_service: str
    fail2ban_banaction: str = "iptables-multiport"
    fail2ban_backend: str = "auto"
    auto_updates_timer: str = ""
    sshd_config_dir: str = "/etc/ssh/sshd_config.d"


class DistroDetectionError(Exception):
    pass


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
            # Debian/Ubuntu log sshd to a file and use the iptables backend.
            fail2ban_banaction="iptables-multiport",
            fail2ban_backend="auto",
            auto_updates_timer="apt-daily-upgrade.timer",
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
            # Fedora/RHEL run firewalld; forcing the iptables backend breaks
            # banning on an nftables system.
            fail2ban_banaction="firewallcmd-ipset",
            fail2ban_backend="systemd",
            # dnf-automatic-install.timer was removed in dnf5 (Fedora 41+).
            # dnf-automatic.timer exists on both dnf4 and dnf5.
            auto_updates_timer="dnf-automatic.timer",
        )
    else:
        raise DistroDetectionError(
            f"Unsupported distribution: {name}. "
            "Only Debian/Ubuntu and Fedora/RHEL are supported."
        )


def is_dnf5() -> bool:
    """Fedora 41+ ships dnf5, which reads an additional config path."""
    try:
        result = subprocess.run(
            ["dnf", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return "dnf5" in result.stdout.lower()


class PackageManager:
    """Abstraction over apt and dnf."""

    def __init__(self, distro: DistroInfo) -> None:
        self.distro = distro

    def resolve(self, package: str) -> str:
        """Map a logical package name onto this distro's real package name."""
        alias = PACKAGE_ALIASES.get(package)
        if not alias:
            return package
        return alias.get(self.distro.package_manager, package) or package

    def install_command(self, packages: list[str]) -> list[str]:
        resolved = [self.resolve(p) for p in packages if self.resolve(p)]
        if self.distro.package_manager == "apt":
            # env(1) rather than a shell prefix — nothing here spawns a shell.
            return [
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                *resolved,
            ]
        return ["dnf", "install", "-y", *resolved]

    def update_command(self) -> list[str]:
        if self.distro.package_manager == "apt":
            return ["apt-get", "update", "-y"]
        return ["dnf", "check-update"]

    def update_ok_returncodes(self) -> tuple[int, ...]:
        if self.distro.package_manager == "apt":
            return (0,)
        # dnf check-update exits 100 when updates are available.
        return (0, 100)


class FirewallAdapter:
    """Abstraction over ufw and firewalld.

    Produces a fully ordered plan rather than isolated commands: the SSH port
    must be opened before the default-deny policy lands, and firewalld has to
    be running before any firewall-cmd call can succeed.
    """

    def __init__(self, distro: DistroInfo) -> None:
        self.distro = distro

    @property
    def supports_rate_limiting(self) -> bool:
        """ufw's `limit` is per-source; firewalld has no per-source equivalent.

        A firewalld rich-rule `limit` applies to the rule as a whole, so it caps
        every client combined and lets an attacker lock the owner out. Fail2Ban
        covers brute-force protection there instead.
        """
        return self.distro.firewall == "ufw"

    def install_packages(self) -> list[str]:
        if self.distro.firewall == "ufw":
            return ["ufw"]
        return ["firewalld"]

    def plan(
        self,
        port: int,
        rate_limiting: bool = True,
        default_deny: bool = True,
        open_ssh_port: bool = True,
    ) -> list[CommandStep]:
        if self.distro.firewall == "ufw":
            return self._ufw_plan(port, rate_limiting, default_deny, open_ssh_port)
        return self._firewalld_plan(port, default_deny, open_ssh_port)

    def _ufw_plan(
        self,
        port: int,
        rate_limiting: bool,
        default_deny: bool,
        open_ssh_port: bool,
    ) -> list[CommandStep]:
        steps: list[CommandStep] = []

        # Open the new port first, so default-deny never lands while nothing
        # is reachable.
        if open_ssh_port:
            if rate_limiting:
                steps.append(CommandStep(
                    f"Allow SSH port {port} with rate limiting",
                    ["ufw", "limit", f"{port}/tcp"],
                ))
            else:
                steps.append(CommandStep(
                    f"Allow SSH port {port}",
                    ["ufw", "allow", f"{port}/tcp"],
                ))

        if port != 22:
            steps.append(CommandStep(
                "Remove default OpenSSH allow rule",
                ["ufw", "delete", "allow", "OpenSSH"],
                ignore_failure=True,
            ))
            steps.append(CommandStep(
                "Remove default port 22 allow rule",
                ["ufw", "delete", "allow", "22/tcp"],
                ignore_failure=True,
            ))

        if default_deny:
            steps.append(CommandStep(
                "Set default deny incoming",
                ["ufw", "default", "deny", "incoming"],
            ))
            steps.append(CommandStep(
                "Set default allow outgoing",
                ["ufw", "default", "allow", "outgoing"],
            ))

        steps.append(CommandStep(
            "Enable ufw",
            ["ufw", "--force", "enable"],
        ))
        return steps

    def _firewalld_plan(
        self,
        port: int,
        default_deny: bool,
        open_ssh_port: bool,
    ) -> list[CommandStep]:
        steps: list[CommandStep] = [
            # firewall-cmd talks to the daemon; it must be up first.
            CommandStep(
                "Enable and start firewalld",
                ["systemctl", "enable", "--now", "firewalld"],
            ),
        ]

        iface = default_interface()
        if iface:
            # Without this the rules below land in the default zone while the
            # real interface sits in another zone, so they govern nothing.
            steps.append(CommandStep(
                f"Bind {iface} to the default firewalld zone",
                ["firewall-cmd", "--permanent", f"--change-interface={iface}"],
                ignore_failure=True,
            ))

        if open_ssh_port:
            steps.append(CommandStep(
                f"Allow SSH port {port}",
                ["firewall-cmd", "--permanent", f"--add-port={port}/tcp"],
            ))

        if port != 22:
            steps.append(CommandStep(
                "Remove default SSH service rule",
                ["firewall-cmd", "--permanent", "--remove-service=ssh"],
                ignore_failure=True,
            ))

        if default_deny:
            # Set the zone's own target rather than switching the default zone:
            # switching zones does not affect an explicitly assigned interface
            # and drops the active session.
            steps.append(CommandStep(
                "Set default deny incoming",
                ["firewall-cmd", "--permanent", "--set-target=DROP"],
            ))

        # One reload at the end, so there is no window where the port is denied
        # but not yet allowed.
        steps.append(CommandStep(
            "Reload firewalld",
            ["firewall-cmd", "--reload"],
        ))
        return steps

    def allow_port_argv(self, port: int) -> list[str]:
        """Single command that opens the SSH port, used as a recovery step."""
        if self.distro.firewall == "ufw":
            return ["ufw", "allow", f"{port}/tcp"]
        return ["firewall-cmd", f"--add-port={port}/tcp"]

    def knock_open_command(self, port: int) -> str:
        """Shell command knockd runs to open the port for a knocking client."""
        if self.distro.firewall == "ufw":
            return f"ufw insert 1 allow from %IP% to any port {port} proto tcp"
        return (
            "firewall-cmd --add-rich-rule="
            f"'rule family=\"ipv4\" source address=\"%IP%\" "
            f"port port=\"{port}\" protocol=\"tcp\" accept'"
        )

    def knock_close_command(self, port: int) -> str:
        if self.distro.firewall == "ufw":
            return f"ufw delete allow from %IP% to any port {port} proto tcp"
        return (
            "firewall-cmd --remove-rich-rule="
            f"'rule family=\"ipv4\" source address=\"%IP%\" "
            f"port port=\"{port}\" protocol=\"tcp\" accept'"
        )


def selinux_port_steps(port: int) -> list[CommandStep]:
    """Label a non-standard SSH port for SELinux.

    Without this, sshd cannot bind the port on an enforcing system and the
    restart fails — the single most common cause of lockout on RHEL family.
    """
    if port == 22:
        return []
    return [
        CommandStep(
            f"Label port {port} as ssh_port_t for SELinux",
            ["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", str(port)],
        ),
    ]


def selinux_port_fallback(port: int) -> list[str]:
    """Used when the port is already defined in the policy and -a fails."""
    return ["semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", str(port)]
