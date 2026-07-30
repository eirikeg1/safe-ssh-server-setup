"""Cross-step lockout checks.

Each step validated fine on its own; the combinations were what locked people
out. These are the combinations the Review step now refuses to apply.
"""

from __future__ import annotations

from safe_ssh_setup.safety import LockoutFacts, evaluate_lockout_risks


def facts(**overrides) -> LockoutFacts:
    base = dict(
        password_auth_enabled=False,
        key_will_be_installed=True,
        existing_key_present=False,
        port_changed=False,
        firewall_step_enabled=True,
        firewall_currently_active=False,
        knocking_enabled=False,
        knocking_acknowledged=False,
        user="eirik",
        allow_users=[],
    )
    base.update(overrides)
    return LockoutFacts(**base)


def test_allow_users_without_the_target_user_is_blocked():
    """AllowUsers that omits the account we install a key for is a lockout."""
    problems = evaluate_lockout_risks(facts(allow_users=["alice", "bob"]))
    assert len(problems) == 1
    assert "does not include" in problems[0]


def test_allow_users_containing_the_target_user_is_fine():
    assert evaluate_lockout_risks(facts(allow_users=["alice", "eirik"])) == []


def test_allow_users_host_pattern_still_matches():
    assert evaluate_lockout_risks(
        facts(allow_users=["eirik@192.168.1.*"])
    ) == []


def test_empty_allow_users_means_unrestricted():
    assert evaluate_lockout_risks(facts(allow_users=[])) == []


def test_a_normal_configuration_is_allowed():
    assert evaluate_lockout_risks(facts()) == []


def test_key_only_auth_without_any_key_is_blocked():
    problems = evaluate_lockout_risks(
        facts(key_will_be_installed=False, existing_key_present=False)
    )
    assert len(problems) == 1
    assert "no SSH public key" in problems[0]


def test_key_only_auth_is_allowed_with_a_preexisting_key():
    """Skipping the key step is fine when authorized_keys already has one."""
    assert evaluate_lockout_risks(
        facts(key_will_be_installed=False, existing_key_present=True)
    ) == []


def test_password_auth_needs_no_key():
    assert evaluate_lockout_risks(
        facts(
            password_auth_enabled=True,
            key_will_be_installed=False,
            existing_key_present=False,
        )
    ) == []


def test_moving_the_port_behind_an_active_firewall_is_blocked():
    problems = evaluate_lockout_risks(
        facts(
            port_changed=True,
            firewall_step_enabled=False,
            firewall_currently_active=True,
        )
    )
    assert len(problems) == 1
    assert "nothing will open the new port" in problems[0]


def test_moving_the_port_is_fine_when_the_firewall_step_runs():
    assert evaluate_lockout_risks(
        facts(
            port_changed=True,
            firewall_step_enabled=True,
            firewall_currently_active=True,
        )
    ) == []


def test_moving_the_port_is_fine_with_no_active_firewall():
    assert evaluate_lockout_risks(
        facts(
            port_changed=True,
            firewall_step_enabled=False,
            firewall_currently_active=False,
        )
    ) == []


def test_port_knocking_requires_acknowledgement():
    problems = evaluate_lockout_risks(
        facts(knocking_enabled=True, knocking_acknowledged=False)
    )
    assert len(problems) == 1
    assert "lockout risk" in problems[0]


def test_acknowledged_port_knocking_is_allowed():
    assert evaluate_lockout_risks(
        facts(knocking_enabled=True, knocking_acknowledged=True)
    ) == []


def test_multiple_problems_are_all_reported():
    problems = evaluate_lockout_risks(
        facts(
            key_will_be_installed=False,
            port_changed=True,
            firewall_step_enabled=False,
            firewall_currently_active=True,
            knocking_enabled=True,
        )
    )
    assert len(problems) == 3
