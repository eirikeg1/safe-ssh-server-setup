"""Cross-step lockout checks.

Each wizard step validates in isolation, but the combinations are what lock
people out: key-only auth with no key installed, a moved port behind a firewall
that was never told about it, port knocking in front of a closed port.

The decision logic is a pure function so it can be tested without a system.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from safe_ssh_setup.models import ActionType, WizardState
from safe_ssh_setup.system import read_authorized_keys, target_user
from safe_ssh_setup.validation import authorized_keys_has_key


@dataclass
class LockoutFacts:
    password_auth_enabled: bool
    key_will_be_installed: bool
    existing_key_present: bool
    port_changed: bool
    firewall_step_enabled: bool
    firewall_currently_active: bool
    knocking_enabled: bool
    knocking_acknowledged: bool
    user: str = "your user"


def evaluate_lockout_risks(facts: LockoutFacts) -> list[str]:
    """Return blocking problems, most severe first. Empty means safe to apply."""
    problems: list[str] = []

    if not facts.password_auth_enabled and not (
        facts.key_will_be_installed or facts.existing_key_present
    ):
        problems.append(
            "Password authentication will be disabled, but no SSH public key "
            f"is installed for {facts.user} and none is planned. You would not "
            "be able to log in. Go back to the SSH Key step and add a key, or "
            "re-enable password authentication in SSH Hardening."
        )

    if facts.port_changed and not facts.firewall_step_enabled and (
        facts.firewall_currently_active
    ):
        problems.append(
            "The SSH port is changing and a firewall is already active, but "
            "the Firewall step is disabled — nothing will open the new port. "
            "Enable the Firewall step, or open the port yourself before "
            "applying."
        )

    if facts.knocking_enabled and not facts.knocking_acknowledged:
        problems.append(
            "Port knocking leaves the SSH port closed until the correct knock "
            "sequence arrives. Confirm you understand the lockout risk on the "
            "Port Knocking step before continuing."
        )

    return problems


def firewall_is_active(firewall: str) -> bool:
    """Whether a firewall is currently filtering traffic."""
    try:
        if firewall == "ufw":
            result = subprocess.run(
                ["sudo", "-n", "--", "ufw", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "status: active" in result.stdout.lower()
        result = subprocess.run(
            ["systemctl", "is-active", "firewalld"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def collect_facts(state: WizardState) -> LockoutFacts:
    key_actions = {
        ActionType.APPEND_AUTHORIZED_KEY,
        ActionType.GENERATE_SSH_KEY,
    }
    key_will_be_installed = any(
        a.action_type in key_actions for a in state.actions
    )
    firewall_step_enabled = any(a.step_name == "firewall" for a in state.actions)
    firewall_name = state.distro_info.firewall if state.distro_info else "ufw"

    return LockoutFacts(
        password_auth_enabled=state.ssh_config.password_authentication,
        key_will_be_installed=key_will_be_installed,
        existing_key_present=authorized_keys_has_key(read_authorized_keys()),
        port_changed=state.ssh_config.port != state.existing_ssh_port,
        firewall_step_enabled=firewall_step_enabled,
        firewall_currently_active=firewall_is_active(firewall_name),
        knocking_enabled=state.port_knocking.enabled,
        knocking_acknowledged=state.port_knocking.risk_acknowledged,
        user=target_user(),
    )


def check_lockout_risks(state: WizardState) -> list[str]:
    return evaluate_lockout_risks(collect_facts(state))
