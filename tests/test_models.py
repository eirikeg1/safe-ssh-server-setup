from safe_ssh_setup.models import (
    STEP_ORDER,
    ActionType,
    Fail2BanConfig,
    PlannedAction,
    SSHConfig,
    WizardState,
    ordered_actions,
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
    assert state.firewall.default_deny is True
    assert state.auto_updates.enabled is True
    assert state.port_knocking.enabled is False
    assert state.port_knocking.risk_acknowledged is False
    assert state.intrusion_detection.enabled is False
    assert state.actions == []
    assert state.applied is False
    assert state.apply_succeeded is False


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


def test_planned_action_defaults_to_safe_values():
    action = PlannedAction(
        action_type=ActionType.WRITE_FILE,
        description="Write config",
        target="/etc/ssh/sshd_config",
        content="Port 2222",
        original_content="Port 22",
        step_name="ssh_hardening",
    )
    assert action.requires_sudo is True
    assert action.critical is False
    assert action.ignore_failure is False
    assert action.ok_returncodes == (0,)
    assert action.command is None


def test_ssh_key_mode_drives_generate_flag():
    state = WizardState()
    assert state.ssh_key.mode == "paste"
    assert state.ssh_key.generate_key is False
    state.ssh_key.mode = "generate"
    assert state.ssh_key.generate_key is True


def test_key_setup_runs_before_hardening_which_runs_before_firewall():
    """Order matters: keys must exist before passwords are disabled, and sshd
    must be verified before the firewall locks the box down."""
    assert STEP_ORDER.index("ssh_key") < STEP_ORDER.index("ssh_hardening")
    assert STEP_ORDER.index("ssh_hardening") < STEP_ORDER.index("firewall")
    assert STEP_ORDER.index("welcome") == 0


def test_ordered_actions_ignores_insertion_order():
    state = WizardState()
    for step in ("firewall", "welcome", "ssh_hardening"):
        state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description=step,
            target="t",
            step_name=step,
        ))

    assert [a.step_name for a in state.plan()] == [
        "welcome", "ssh_hardening", "firewall",
    ]


def test_unknown_steps_sort_last():
    actions = [
        PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="x",
            target="t",
            step_name="mystery",
        ),
        PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="y",
            target="t",
            step_name="welcome",
        ),
    ]
    assert [a.step_name for a in ordered_actions(actions)] == ["welcome", "mystery"]


def test_wizard_state_action_filtering():
    state = WizardState()
    for step in ("fail2ban", "firewall", "fail2ban"):
        state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="a",
            target="t",
            step_name=step,
        ))

    state.actions = [a for a in state.actions if a.step_name != "fail2ban"]
    assert len(state.actions) == 1
    assert state.actions[0].step_name == "firewall"
