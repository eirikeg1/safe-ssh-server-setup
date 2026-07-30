"""Screen-level tests.

The wizard used to keep its state in widgets: navigating Back and then Next
rebuilt a screen with hardcoded defaults, silently discarding what the user had
entered. Screens now derive every value from WizardState, and Skip undoes the
step instead of leaving its actions in the plan.
"""

from __future__ import annotations

import asyncio

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, RadioButton, Switch, TextArea

from safe_ssh_setup.models import ActionType, PlannedAction, WizardState
from safe_ssh_setup.screens.apply import ApplyScreen
from safe_ssh_setup.screens.auto_updates import AutoUpdatesScreen
from safe_ssh_setup.screens.fail2ban import Fail2BanScreen
from safe_ssh_setup.screens.firewall import FirewallScreen
from safe_ssh_setup.screens.intrusion_detection import IntrusionDetectionScreen
from safe_ssh_setup.screens.port_knocking import PortKnockingScreen
from safe_ssh_setup.screens.ssh_hardening import SSHHardeningScreen
from safe_ssh_setup.screens.ssh_key import SSHKeyScreen
from safe_ssh_setup.screens.ssh_port import SSHPortScreen
from safe_ssh_setup.screens.summary import SummaryScreen
from safe_ssh_setup.system import target_user


class ScreenHost(App):
    """Minimal app so screens can be mounted without the whole wizard."""

    @property
    def step_labels(self) -> list[str]:
        return [f"S{i}" for i in range(12)]

    def compose(self) -> ComposeResult:
        return []


def drive(screen, body=None):
    """Mount `screen`, run `body(screen)` in the event loop, return its result.

    The body has to run while the app is alive: once run_test() exits the
    screen is torn down and queries find nothing.
    """
    captured = {}

    async def _run():
        app = ScreenHost()
        async with app.run_test() as pilot:
            # Awaited so the screen is fully composed before we inspect it.
            await app.push_screen(screen)
            await pilot.pause()
            if body is not None:
                captured["result"] = body(screen)
            await pilot.pause()

    asyncio.run(_run())
    return captured.get("result")


def make_screen(cls, state, step_index=1):
    return cls(state=state, step_index=step_index, total_steps=12)


def snapshot(screen) -> dict:
    """Widget values captured while the screen is still mounted."""
    return {
        "inputs": {w.id: w.value for w in screen.query(Input)},
        "switches": {w.id: w.value for w in screen.query(Switch)},
        "radios": {w.id: w.value for w in screen.query(RadioButton)},
        "radio_labels": {w.id: w.label.plain for w in screen.query(RadioButton)},
        "textareas": {w.id: w.text for w in screen.query(TextArea)},
    }


@pytest.fixture
def state(fedora) -> WizardState:
    wizard = WizardState()
    wizard.distro_info = fedora
    wizard.distro = fedora.family
    wizard.ssh_service = fedora.ssh_service
    return wizard


@pytest.fixture(autouse=True)
def isolated_system(monkeypatch):
    """Keep screens away from the real host."""
    monkeypatch.setattr(
        "safe_ssh_setup.sudo.SudoHelper.read_file", staticmethod(lambda path: "")
    )
    monkeypatch.setattr(
        "safe_ssh_setup.screens.ssh_hardening.sftp_server_path",
        lambda: "/usr/libexec/openssh/sftp-server",
    )
    monkeypatch.setattr(
        "safe_ssh_setup.screens.ssh_hardening.selinux_enabled", lambda: True
    )
    monkeypatch.setattr(
        "safe_ssh_setup.screens.ssh_port.listening_ports", lambda: {22}
    )
    monkeypatch.setattr(
        "safe_ssh_setup.screens.ssh_port.ephemeral_port_floor", lambda: 32768
    )
    monkeypatch.setattr(
        "safe_ssh_setup.screens.port_knocking.default_interface", lambda: "enp3s0"
    )
    monkeypatch.setattr(
        "safe_ssh_setup.screens.firewall.default_interface", lambda: "enp3s0"
    )


# ------------------------------------------------------- rehydration tests


def test_hardening_screen_shows_saved_values_not_defaults(state):
    """Regression: revisiting this screen used to reset every field."""
    state.ssh_config.max_auth_tries = 7
    state.ssh_config.login_grace_time = 45
    state.ssh_config.password_authentication = True
    state.ssh_config.x11_forwarding = True
    state.ssh_config.permit_root_login = "yes"
    state.ssh_config.ciphers = ["aes256-gcm@openssh.com"]

    snap = drive(make_screen(SSHHardeningScreen, state), snapshot)

    assert snap["inputs"]["max-auth-tries"] == "7"
    assert snap["inputs"]["login-grace-time"] == "45"
    assert snap["inputs"]["ciphers"] == "aes256-gcm@openssh.com"
    # "Key-only auth" is off because password auth was turned on.
    assert snap["switches"]["key-only-auth"] is False
    assert snap["switches"]["x11-fwd"] is True
    assert snap["switches"]["disable-root"] is False


def test_port_screen_remembers_custom_port(state):
    state.port_choice = "custom"
    state.ssh_config.port = 2222

    snap = drive(make_screen(SSHPortScreen, state), snapshot)

    assert snap["inputs"]["custom-port"] == "2222"
    assert snap["radios"]["radio-custom"] is True


def test_port_screen_keeps_the_same_random_port_across_visits(state):
    drive(make_screen(SSHPortScreen, state), snapshot)
    chosen = state.random_port
    assert chosen

    snap = drive(make_screen(SSHPortScreen, state), snapshot)
    assert state.random_port == chosen
    assert str(chosen) in snap["radio_labels"]["radio-random"]


def test_key_screen_restores_a_pasted_key(state, public_key):
    state.ssh_key.public_key = public_key
    snap = drive(make_screen(SSHKeyScreen, state), snapshot)
    assert snap["textareas"]["pubkey-input"] == public_key


def test_fail2ban_screen_shows_saved_values(state):
    state.fail2ban.max_retry = 9
    state.fail2ban.ban_time = 7200
    state.fail2ban.enabled = False

    snap = drive(make_screen(Fail2BanScreen, state), snapshot)

    assert snap["inputs"]["max-retry"] == "9"
    assert snap["inputs"]["ban-time"] == "7200"
    assert snap["switches"]["enable-f2b"] is False


def test_knocking_screen_shows_saved_sequence(state):
    state.port_knocking.sequence = [1111, 2222, 3333]
    state.port_knocking.enabled = True
    state.port_knocking.risk_acknowledged = True

    snap = drive(make_screen(PortKnockingScreen, state), snapshot)

    assert snap["inputs"]["knock-sequence"] == "1111,2222,3333"
    assert snap["switches"]["ack-knock"] is True


# --------------------------------------------------------------- skip tests


@pytest.mark.parametrize(
    "screen_cls,step_name,flag",
    [
        (Fail2BanScreen, "fail2ban", "fail2ban"),
        (FirewallScreen, "firewall", "firewall"),
        (AutoUpdatesScreen, "auto_updates", "auto_updates"),
        (PortKnockingScreen, "port_knocking", "port_knocking"),
        (IntrusionDetectionScreen, "intrusion_detection", "intrusion_detection"),
    ],
)
def test_skip_removes_previously_planned_actions(state, screen_cls, step_name, flag):
    """Configuring a step then skipping it used to still apply the step."""
    state.actions.append(PlannedAction(
        action_type=ActionType.RUN_COMMAND,
        description="left over from an earlier visit",
        target="t",
        command=["true"],
        step_name=step_name,
    ))
    getattr(state, flag).enabled = True

    screen = make_screen(screen_cls, state)
    screen.skip_step()

    assert state.actions == []
    assert getattr(state, flag).enabled is False


# --------------------------------------------------------- planning output


def test_hardening_plans_validation_restart_and_verification(state):
    state.ssh_config.port = 2222

    drive(make_screen(SSHHardeningScreen, state), lambda s: s.save_state())

    descriptions = [a.description for a in state.actions]
    assert "Validate sshd_config syntax" in descriptions
    assert "Restart SSH daemon" in descriptions
    assert any(a.action_type == ActionType.VERIFY_SSH for a in state.actions)

    # Each of these must abort the run rather than let the firewall follow on.
    critical = {a.description for a in state.actions if a.critical}
    assert "Validate sshd_config syntax" in critical
    assert "Restart SSH daemon" in critical


def test_hardening_defaults_to_restricting_login_to_the_current_user(state):
    snap = drive(make_screen(SSHHardeningScreen, state), snapshot)
    assert snap["switches"]["limit-users"] is True
    assert snap["inputs"]["allow-users"] == target_user()


def test_hardening_remembers_an_unrestricted_choice(state):
    state.ssh_config.restrict_users = False
    state.ssh_config.allow_users = []

    snap = drive(make_screen(SSHHardeningScreen, state), snapshot)
    assert snap["switches"]["limit-users"] is False


def test_hardening_saves_the_allowed_user_list(state):
    def body(screen):
        screen.query_one("#allow-users").value = f"{target_user()}, root"
        screen.save_state()

    drive(make_screen(SSHHardeningScreen, state), body)
    assert state.ssh_config.allow_users == [target_user(), "root"]


def test_hardening_rejects_an_allow_list_without_the_target_user(state):
    def body(screen):
        screen.query_one("#allow-users").value = "root"
        screen._result = screen.validate_step()

    screen = make_screen(SSHHardeningScreen, state)
    drive(screen, body)
    assert screen._result is not None
    assert "not in the allowed users list" in screen._result


def test_hardening_rejects_a_misspelled_username(state):
    def body(screen):
        screen.query_one("#allow-users").value = "definitely-not-a-real-account"
        screen._result = screen.validate_step()

    screen = make_screen(SSHHardeningScreen, state)
    drive(screen, body)
    assert screen._result is not None
    assert "No such account" in screen._result


def test_hardening_generates_host_keys_before_validating(state):
    """sshd -t exits 1 with "no hostkeys available" on a machine where the
    daemon has never been started, because sshd.service normally creates them
    on first start."""
    drive(make_screen(SSHHardeningScreen, state), lambda s: s.save_state())

    commands = [a.command for a in state.actions if a.command]
    keygen = next(i for i, c in enumerate(commands) if c == ["ssh-keygen", "-A"])
    validate = next(i for i, c in enumerate(commands) if c[:2] == ["sshd", "-t"])
    assert keygen < validate

    action = next(a for a in state.actions if a.command == ["ssh-keygen", "-A"])
    assert action.critical


def test_hardening_labels_the_port_for_selinux_on_rhel(state):
    state.ssh_config.port = 2222
    drive(make_screen(SSHHardeningScreen, state), lambda s: s.save_state())

    semanage = [
        a for a in state.actions if a.command and a.command[0] == "semanage"
    ]
    assert len(semanage) == 1
    assert semanage[0].command == [
        "semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", "2222",
    ]
    assert semanage[0].fallback_command[2] == "-m"
    assert semanage[0].critical


def test_hardening_skips_selinux_labelling_on_port_22(state):
    state.ssh_config.port = 22
    drive(make_screen(SSHHardeningScreen, state), lambda s: s.save_state())
    assert not [a for a in state.actions if a.command and a.command[0] == "semanage"]


def test_hardening_commands_are_argv_lists(state):
    drive(make_screen(SSHHardeningScreen, state), lambda s: s.save_state())
    for action in state.actions:
        if action.command is not None:
            assert isinstance(action.command, list)
            assert all(isinstance(part, str) for part in action.command)


def test_key_screen_plans_a_native_append_with_no_shell(state, public_key):
    def body(screen):
        screen.query_one("#pubkey-input").text = public_key
        screen.save_state()

    drive(make_screen(SSHKeyScreen, state), body)

    appends = [
        a for a in state.actions
        if a.action_type == ActionType.APPEND_AUTHORIZED_KEY
    ]
    assert len(appends) == 1
    assert appends[0].public_key == public_key
    # No shell anywhere in this step: nothing can interpret the key as code.
    assert all(
        a.command is None or "sh" not in a.command[0]
        for a in state.actions
    )


def test_key_screen_rejects_an_injection_payload(state):
    def body(screen):
        screen.query_one("#pubkey-input").text = (
            'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI $(touch /tmp/pwned)'
        )
        assert screen.validate_step() is not None

    drive(make_screen(SSHKeyScreen, state), body)


def test_firewall_leaves_port_closed_when_knocking_is_enabled(state):
    state.ssh_config.port = 2222
    state.port_knocking.enabled = True

    drive(make_screen(FirewallScreen, state), lambda s: s.save_state())

    argvs = [" ".join(a.command) for a in state.actions if a.command]
    assert not any("--add-port=2222/tcp" in a for a in argvs)


def test_firewall_opens_the_port_when_knocking_is_off(state):
    state.ssh_config.port = 2222
    state.port_knocking.enabled = False

    drive(make_screen(FirewallScreen, state), lambda s: s.save_state())

    argvs = [" ".join(a.command) for a in state.actions if a.command]
    assert any("--add-port=2222/tcp" in a for a in argvs)


def test_auto_updates_enables_a_timer_that_exists(state):
    drive(make_screen(AutoUpdatesScreen, state), lambda s: s.save_state())

    timers = [
        a.command for a in state.actions
        if a.command and a.command[:2] == ["systemctl", "enable"]
    ]
    assert timers == [["systemctl", "enable", "--now", "dnf-automatic.timer"]]


def test_port_screen_allows_keeping_the_port_sshd_already_uses(state, monkeypatch):
    """Keeping port 22 used to be rejected as "already in use" by sshd itself."""
    state.existing_ssh_port = 22
    state.port_choice = "default"

    screen = make_screen(SSHPortScreen, state)
    drive(screen, lambda s: setattr(s, "_result", s.validate_step()))
    assert screen._result is None


def test_apply_screen_does_not_run_twice(state, monkeypatch):
    """Back-then-Next from Summary used to re-run the whole plan against the
    files this run had already rewritten, destroying the backup baseline."""
    executed = []
    monkeypatch.setattr(
        "safe_ssh_setup.screens.apply.ActionExecutor",
        lambda *a, **k: executed.append(a) or pytest.fail("executor was built"),
    )

    state.applied = True
    state.apply_results = [("Restart SSH daemon", True, "OK")]
    state.actions = [PlannedAction(
        action_type=ActionType.RUN_COMMAND,
        description="should not run",
        target="t",
        command=["true"],
        step_name="firewall",
    )]

    screen = make_screen(ApplyScreen, state, step_index=10)
    status = drive(screen, lambda s: str(s.query_one("#status-label").render()))

    assert executed == []
    assert "Already applied" in status


def test_apply_and_summary_cannot_navigate_back(state):
    """No Back button means the plan cannot be replayed from Summary."""
    assert ApplyScreen.can_go_back is False
    assert SummaryScreen.can_go_back is False


def test_port_screen_still_rejects_a_port_owned_by_something_else(state):
    # sshd lives on 2200, so the listening port 22 belongs to something else.
    state.existing_ssh_port = 2200
    state.port_choice = "custom"

    def body(screen):
        screen.query_one("#custom-port").value = "22"
        screen._result = screen.validate_step()

    screen = make_screen(SSHPortScreen, state)
    drive(screen, body)
    assert screen._result is not None
    assert "already in use" in screen._result
