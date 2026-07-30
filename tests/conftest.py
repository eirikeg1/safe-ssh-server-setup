from __future__ import annotations

import base64
import subprocess

import pytest

from safe_ssh_setup.distro import DistroInfo
from safe_ssh_setup.models import DistroFamily


def make_public_key(
    key_type: str = "ssh-ed25519",
    comment: str = "user@host",
) -> str:
    """A structurally valid public key: length-prefixed type plus key data."""
    body = key_type.encode()
    blob = base64.b64encode(
        len(body).to_bytes(4, "big") + body + b"\x00" * 32
    ).decode()
    return f"{key_type} {blob}" + (f" {comment}" if comment else "")


@pytest.fixture
def public_key() -> str:
    return make_public_key()


class FakeSudo:
    """Stand-in for SudoHelper that records argv instead of running anything."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.existing: set[str] = set()
        self.commands: list[list[str]] = []
        self.returncodes: dict[tuple[str, ...], int] = {}
        self.stdout: dict[tuple[str, ...], str] = {}
        self.refresh_calls = 0

    # -- credential handling -------------------------------------------------
    def refresh_credentials(self) -> bool:
        self.refresh_calls += 1
        return True

    def check_sudo_available(self) -> bool:
        return True

    # -- file helpers --------------------------------------------------------
    def file_exists(self, path: str) -> bool:
        return path in self.existing or path in self.files

    def read_file(self, path: str) -> str | None:
        return self.files.get(path)

    def write_file(
        self,
        path: str,
        content: str,
        mode: str = "0644",
        owner: str = "root:root",
    ) -> None:
        self.files[path] = content

    # -- command execution ---------------------------------------------------
    def _complete(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        key = tuple(argv)
        return subprocess.CompletedProcess(
            argv,
            self.returncodes.get(key, 0),
            stdout=self.stdout.get(key, ""),
            stderr="" if self.returncodes.get(key, 0) == 0 else "boom",
        )

    def run(self, argv, check=False, timeout=None):
        argv = list(argv)
        self.commands.append(argv)
        result = self._complete(argv)
        if result.returncode == 0 and argv[0] == "cp" and len(argv) >= 3:
            self.files[argv[-1]] = self.files.get(argv[-2], "")
            self.existing.add(argv[-1])
        return result

    def run_as_user(self, argv, check=False, timeout=None):
        return self.run(argv, check=check, timeout=timeout)


@pytest.fixture
def fake_sudo() -> FakeSudo:
    return FakeSudo()


@pytest.fixture
def debian() -> DistroInfo:
    return DistroInfo(
        family=DistroFamily.DEBIAN,
        name="Ubuntu",
        version="24.04",
        package_manager="apt",
        firewall="ufw",
        auto_updates_package="unattended-upgrades",
        ssh_service="ssh",
        fail2ban_banaction="iptables-multiport",
        fail2ban_backend="auto",
        auto_updates_timer="apt-daily-upgrade.timer",
    )


@pytest.fixture
def fedora() -> DistroInfo:
    return DistroInfo(
        family=DistroFamily.RHEL,
        name="Fedora Linux",
        version="43",
        package_manager="dnf",
        firewall="firewalld",
        auto_updates_package="dnf-automatic",
        ssh_service="sshd",
        fail2ban_banaction="firewallcmd-ipset",
        fail2ban_backend="systemd",
        auto_updates_timer="dnf-automatic.timer",
    )
