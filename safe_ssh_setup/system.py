"""System introspection helpers.

Nothing in here may import :mod:`safe_ssh_setup.sudo` at module level — that
module imports this one for user resolution.
"""

from __future__ import annotations

import os
import pwd
import re
import subprocess
from pathlib import Path

# sftp-server lives in different places per distro. Ordered by likelihood.
SFTP_SERVER_CANDIDATES = (
    "/usr/libexec/openssh/sftp-server",
    "/usr/lib/openssh/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/sftp-server",
)

SSHD_BINARY_CANDIDATES = (
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
)

DEFAULT_EPHEMERAL_LOW = 32768


def target_user() -> str:
    """The user whose ~/.ssh we are configuring.

    Under ``sudo`` the process euid is 0, but the account that should own the
    SSH keys is the one named by SUDO_USER.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER") or "root"


def target_uid_gid() -> tuple[int, int]:
    entry = pwd.getpwnam(target_user())
    return entry.pw_uid, entry.pw_gid


def target_home() -> Path:
    """Home directory of :func:`target_user`, never root's home under sudo."""
    try:
        return Path(pwd.getpwnam(target_user()).pw_dir)
    except KeyError:
        return Path.home()


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


def running_as_root_without_sudo_user() -> bool:
    """True when invoked directly as root rather than escalated via sudo."""
    return os.geteuid() == 0 and not os.environ.get("SUDO_USER")


def is_ssh_session() -> bool:
    return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"))


def selinux_enabled() -> bool:
    """True when an SELinux policy is loaded (enforcing or permissive).

    Ports must be labelled in permissive mode too, otherwise the box breaks the
    moment SELinux is flipped back to enforcing.
    """
    return Path("/sys/fs/selinux/enforce").exists()


def sftp_server_path() -> str:
    """Path to sftp-server, or the built-in subsystem when no binary exists.

    ``sshd -t`` does not check that the Subsystem path exists, so hardcoding the
    wrong one silently breaks sftp and scp.
    """
    for candidate in SFTP_SERVER_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return "internal-sftp"


def sshd_binary_installed() -> bool:
    """Whether the SSH *server* is installed.

    Deliberately does not consult PATH: /usr/sbin is absent from a non-root
    user's PATH on Debian, and the ssh *client* being present says nothing
    about the server.
    """
    return any(Path(p).exists() for p in SSHD_BINARY_CANDIDATES)


def systemd_available() -> bool:
    return Path("/run/systemd/system").exists()


def default_interface() -> str | None:
    """Interface carrying the default route, e.g. ``enp3s0``."""
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    match = re.search(r"\bdev\s+(\S+)", result.stdout)
    return match.group(1) if match else None


def listening_ports() -> set[int]:
    """TCP ports with a listening socket, via ``ss``."""
    ports: set[int] = set()
    try:
        result = subprocess.run(
            ["ss", "-tlnH"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ports

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        _, _, port_str = local.rpartition(":")
        if port_str.isdigit():
            ports.add(int(port_str))
    return ports


def ephemeral_port_floor() -> int:
    """Lowest port the kernel hands out for outbound connections."""
    try:
        raw = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
        return int(raw[0])
    except (OSError, ValueError, IndexError):
        return DEFAULT_EPHEMERAL_LOW


def configured_sshd_port(config_path: str = "/etc/ssh/sshd_config") -> int:
    """The port sshd is currently configured to use.

    Used so that re-running the wizard, or keeping the existing port, is not
    rejected as "already in use" by sshd itself.
    """
    from safe_ssh_setup.sudo import SudoHelper

    content = SudoHelper.read_file(config_path)
    return parse_sshd_port(content)


def parse_sshd_port(content: str | None) -> int:
    if not content:
        return 22
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^Port\s+(\d{1,5})\s*$", stripped, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return 22


def read_authorized_keys(path: Path | None = None) -> str:
    keys_path = path or (target_home() / ".ssh" / "authorized_keys")
    try:
        return keys_path.read_text()
    except OSError:
        return ""
