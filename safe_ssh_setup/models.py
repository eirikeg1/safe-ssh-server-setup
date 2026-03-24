from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


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


@dataclass
class PlannedAction:
    action_type: ActionType
    description: str
    target: str
    content: str | None = None
    original_content: str | None = None
    command: str | None = None
    permissions: str | None = None
    owner: str | None = None
    requires_sudo: bool = True
    step_name: str = ""


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


@dataclass
class AutoUpdatesConfig:
    enabled: bool = True


@dataclass
class PortKnockingConfig:
    enabled: bool = False
    sequence: list[int] = field(default_factory=lambda: [7000, 8000, 9000])
    seq_timeout: int = 5


@dataclass
class IntrusionDetectionConfig:
    enabled: bool = False


@dataclass
class SSHKeyConfig:
    generate_key: bool = True
    key_type: str = "ed25519"
    key_path: Path | None = None
    setup_authorized_keys: bool = True


@dataclass
class WizardState:
    distro: DistroFamily | None = None
    distro_name: str = ""

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


@dataclass
class BackupManifest:
    timestamp: str
    backup_dir: Path
    backed_up_files: list[tuple[str, str]]
    rollback_script: Path
