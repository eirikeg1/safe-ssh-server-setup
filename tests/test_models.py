from safe_ssh_setup.models import (
    ActionType,
    Fail2BanConfig,
    PlannedAction,
    SSHConfig,
    WizardState,
)


def test_wizard_state_defaults():
    state = WizardState()
    assert state.distro is None
    assert state.ssh_service == "sshd"
    assert state.ssh_config.port == 22
    assert state.ssh_config.password_authentication is False
    assert state.ssh_config.pubkey_authentication is True
    assert state.ssh_config.permit_root_login == "no"
    assert state.fail2ban.enabled is True
    assert state.firewall.enabled is True
    assert state.auto_updates.enabled is True
    assert state.port_knocking.enabled is False
    assert state.intrusion_detection.enabled is False
    assert state.actions == []
    assert state.applied is False


def test_ssh_config_strong_defaults():
    cfg = SSHConfig()
    assert cfg.x11_forwarding is False
    assert cfg.allow_agent_forwarding is False
    assert cfg.allow_tcp_forwarding is False
    assert cfg.max_auth_tries == 3
    assert cfg.login_grace_time == 30
    assert "chacha20-poly1305@openssh.com" in cfg.ciphers
    assert "hmac-sha2-512-etm@openssh.com" in cfg.macs
    assert "curve25519-sha256" in cfg.kex_algorithms


def test_fail2ban_config_defaults():
    cfg = Fail2BanConfig()
    assert cfg.enabled is True
    assert cfg.max_retry == 5
    assert cfg.find_time == 600
    assert cfg.ban_time == 3600


def test_planned_action_creation():
    action = PlannedAction(
        action_type=ActionType.WRITE_FILE,
        description="Write config",
        target="/etc/ssh/sshd_config",
        content="Port 2222",
        original_content="Port 22",
        step_name="ssh_hardening",
    )
    assert action.action_type == ActionType.WRITE_FILE
    assert action.requires_sudo is True
    assert action.step_name == "ssh_hardening"


def test_wizard_state_action_filtering():
    state = WizardState()
    state.actions.append(PlannedAction(
        action_type=ActionType.RUN_COMMAND,
        description="a",
        target="t",
        step_name="fail2ban",
    ))
    state.actions.append(PlannedAction(
        action_type=ActionType.RUN_COMMAND,
        description="b",
        target="t",
        step_name="firewall",
    ))
    state.actions.append(PlannedAction(
        action_type=ActionType.RUN_COMMAND,
        description="c",
        target="t",
        step_name="fail2ban",
    ))

    # Filter out fail2ban actions
    state.actions = [a for a in state.actions if a.step_name != "fail2ban"]
    assert len(state.actions) == 1
    assert state.actions[0].step_name == "firewall"
