from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from safe_ssh_setup.distro import DistroInfo


class DistroFamily(Enum):
    DEBIAN = auto()
    RHEL = auto()


class ActionType(Enum):
    WRITE_FILE = auto()
    INSTALL_PACKAGE = auto()
    ENABLE_SERVICE = auto()
    RESTART_SERVICE = auto()
    RUN_COMMAND = auto()
    CREATE_DIR = auto()
    SET_PERMISSIONS = auto()
    APPEND_AUTHORIZED_KEY = auto()
    GENERATE_SSH_KEY = auto()
    VERIFY_SSH = auto()


# Execution order is fixed by step, not by the order the user happened to visit
# the wizard. sshd is configured and verified *before* the firewall locks the
# box down, so that a failed sshd restart aborts while the old rules still work.
STEP_ORDER = (
    "welcome",
    "ssh_key",
    "ssh_hardening",
    "fail2ban",
    "firewall",
    "auto_updates",
    "port_knocking",
    "intrusion_detection",
)


@dataclass
class PlannedAction:
    action_type: ActionType
    description: str
    target: str
    content: str | None = None
    original_content: str | None = None
    # argv, never a shell string: the executor does not spawn a shell.
    command: list[str] | None = None
    # Run only if `command` fails; used for "add or modify" style operations.
    fallback_command: list[str] | None = None
    permissions: str | None = None
    owner: str | None = None
    requires_sudo: bool = True
    # Exit codes that mean success (dnf check-update returns 100, for example).
    ok_returncodes: tuple[int, ...] = (0,)
    # Best-effort steps whose failure must not stop the run.
    ignore_failure: bool = False
    # Failure aborts the run and triggers the sshd restore path.
    critical: bool = False
    step_name: str = ""

    # Payloads for actions the executor performs natively (no shell).
    public_key: str | None = None
    key_path: str | None = None
    port: int | None = None
    service: str | None = None


def ordered_actions(actions: list[PlannedAction]) -> list[PlannedAction]:
    """Sort actions into canonical step order, stable within a step."""
    rank = {name: i for i, name in enumerate(STEP_ORDER)}
    return sorted(actions, key=lambda a: rank.get(a.step_name, len(rank)))


@dataclass
class SSHConfig:
    port: int = 22
    permit_root_login: str = "no"
    pubkey_authentication: bool = True
    password_authentication: bool = False
    permit_empty_passwords: bool = False
    kbd_interactive_auth: bool = False
    max_auth_tries: int = 3
    login_grace_time: int = 30
    client_alive_interval: int = 300
    client_alive_count_max: int = 2
    x11_forwarding: bool = False
    allow_agent_forwarding: bool = False
    allow_tcp_forwarding: bool = False
    # restrict_users distinguishes "not configured yet" from "deliberately
    # unrestricted"; allow_users is empty in both cases.
    restrict_users: bool = True
    allow_users: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=lambda: [
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
    ])
    macs: list[str] = field(default_factory=lambda: [
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
    ])
    kex_algorithms: list[str] = field(default_factory=lambda: [
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
    ])


@dataclass
class Fail2BanConfig:
    enabled: bool = True
    max_retry: int = 5
    find_time: int = 600
    ban_time: int = 3600


@dataclass
class FirewallConfig:
    enabled: bool = True
    rate_limiting: bool = True
    default_deny: bool = True


@dataclass
class AutoUpdatesConfig:
    enabled: bool = True


@dataclass
class PortKnockingConfig:
    enabled: bool = False
    sequence: list[int] = field(default_factory=lambda: [7000, 8000, 9000])
    seq_timeout: int = 5
    # Knocking closes the SSH port by default, so the risk must be acknowledged.
    risk_acknowledged: bool = False


@dataclass
class IntrusionDetectionConfig:
    enabled: bool = False


@dataclass
class SSHKeyConfig:
    mode: str = "paste"  # "paste" | "generate"
    key_type: str = "ed25519"
    key_path: Path | None = None
    public_key: str = ""
    setup_authorized_keys: bool = True

    @property
    def generate_key(self) -> bool:
        return self.mode == "generate"


@dataclass
class WizardState:
    distro: DistroFamily | None = None
    distro_info: DistroInfo | None = None
    distro_name: str = ""
    ssh_service: str = "sshd"

    # Remembered so re-entering the port screen doesn't roll a different port.
    port_choice: str = "random"
    random_port: int = 0
    # Port sshd is on right now; keeping it must not count as "in use".
    existing_ssh_port: int = 22

    ssh_config: SSHConfig = field(default_factory=SSHConfig)
    ssh_key: SSHKeyConfig = field(default_factory=SSHKeyConfig)
    fail2ban: Fail2BanConfig = field(default_factory=Fail2BanConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    auto_updates: AutoUpdatesConfig = field(default_factory=AutoUpdatesConfig)
    port_knocking: PortKnockingConfig = field(default_factory=PortKnockingConfig)
    intrusion_detection: IntrusionDetectionConfig = field(
        default_factory=IntrusionDetectionConfig,
    )

    actions: list[PlannedAction] = field(default_factory=list)

    backup_dir: Path | None = None
    applied: bool = False
    apply_in_progress: bool = False
    apply_succeeded: bool = False
    apply_results: list[tuple[str, bool, str]] = field(default_factory=list)

    def plan(self) -> list[PlannedAction]:
        return ordered_actions(self.actions)


@dataclass
class BackupManifest:
    timestamp: str
    backup_dir: Path
    # (original_path, backup_path) for files that existed beforehand.
    backed_up_files: list[tuple[str, str]]
    # Paths this run created; rollback deletes them.
    created_files: list[str]
    rollback_script: Path
    services_enabled: list[str] = field(default_factory=list)
