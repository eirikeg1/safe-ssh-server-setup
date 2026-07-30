"""Executor regression tests.

Covers the failures that made the original apply step unsafe: successes
reported for failed runs, a rollback script written only after everything
succeeded, created files that rollback never removed, and a failed sshd
restart that did not stop the firewall from locking the box down.
"""

from __future__ import annotations


import pytest

from safe_ssh_setup import executor as executor_module
from safe_ssh_setup.executor import ActionExecutor
from safe_ssh_setup.models import (
    ActionType,
    PlannedAction,
    WizardState,
    ordered_actions,
)


def make_executor(fake_sudo, state=None) -> ActionExecutor:
    return ActionExecutor(state or WizardState(), sudo=fake_sudo)


def run_command_action(**kwargs) -> PlannedAction:
    defaults = dict(
        action_type=ActionType.RUN_COMMAND,
        description="do a thing",
        target="thing",
        command=["true"],
        step_name="firewall",
    )
    defaults.update(kwargs)
    return PlannedAction(**defaults)


# --------------------------------------------------------------- backup dir


def test_rollback_script_exists_before_any_action_runs(fake_sudo):
    """A crash mid-apply must still leave a usable rollback script."""
    ex = make_executor(fake_sudo)
    backup_dir = ex.prepare_backup_dir()

    rollback = fake_sudo.files.get(f"{backup_dir}/rollback.sh")
    manifest = fake_sudo.files.get(f"{backup_dir}/manifest.json")
    assert rollback is not None
    assert rollback.startswith("#!/bin/bash")
    assert manifest is not None


def test_backup_dir_collision_gets_a_unique_name(fake_sudo):
    ex = make_executor(fake_sudo)
    first = ex.prepare_backup_dir()
    fake_sudo.existing.add(str(first))

    second = make_executor(fake_sudo).prepare_backup_dir()
    assert second != first
    assert str(second).endswith("-2")


# ------------------------------------------------------------ file tracking


def test_created_files_are_recorded_and_removed_by_rollback(fake_sudo):
    """Files that did not exist before must be deleted on rollback."""
    ex = make_executor(fake_sudo)
    ex.prepare_backup_dir()

    ex.execute_action(PlannedAction(
        action_type=ActionType.WRITE_FILE,
        description="Write jail",
        target="/etc/fail2ban/jail.local",
        content="[sshd]\n",
        step_name="fail2ban",
    ))

    assert ex.manifest.created_files == ["/etc/fail2ban/jail.local"]
    script = fake_sudo.files[f"{ex.backup_dir}/rollback.sh"]
    assert "rm -f /etc/fail2ban/jail.local" in script


def test_modified_files_are_backed_up_and_restored_by_rollback(fake_sudo):
    fake_sudo.files["/etc/ssh/sshd_config"] = "Port 22\n"
    ex = make_executor(fake_sudo)
    ex.prepare_backup_dir()

    ex.execute_action(PlannedAction(
        action_type=ActionType.WRITE_FILE,
        description="Write sshd_config",
        target="/etc/ssh/sshd_config",
        content="Port 2222\n",
        step_name="ssh_hardening",
    ))

    assert ex.manifest.backed_up_files
    original, backup = ex.manifest.backed_up_files[0]
    assert original == "/etc/ssh/sshd_config"
    script = fake_sudo.files[f"{ex.backup_dir}/rollback.sh"]
    assert f"cp -p {backup} /etc/ssh/sshd_config" in script
    assert ex.manifest.created_files == []


def test_rollback_script_does_not_use_set_e(fake_sudo):
    """set -e would abandon the restore at the first failing file."""
    ex = make_executor(fake_sudo)
    ex.prepare_backup_dir()
    script = fake_sudo.files[f"{ex.backup_dir}/rollback.sh"]
    assert "set -e\n" not in script
    assert "set -u" in script


def test_rollback_script_lists_what_it_cannot_revert(fake_sudo):
    ex = make_executor(fake_sudo)
    ex.prepare_backup_dir()
    script = fake_sudo.files[f"{ex.backup_dir}/rollback.sh"]
    assert "NOT reverted automatically" in script
    assert "firewall rules" in script


# ------------------------------------------------------------ command rules


def test_commands_are_argv_never_shell_strings(fake_sudo):
    ex = make_executor(fake_sudo)
    ex.prepare_backup_dir()
    ex.execute_action(run_command_action(command=["ufw", "allow", "2222/tcp"]))
    assert ["ufw", "allow", "2222/tcp"] in fake_sudo.commands


def test_nonzero_exit_is_a_failure(fake_sudo):
    fake_sudo.returncodes[("false",)] = 1
    ex = make_executor(fake_sudo)
    ok, message = ex.execute_action(run_command_action(command=["false"]))
    assert not ok
    assert "exit 1" in message


def test_ok_returncodes_allow_dnf_check_update(fake_sudo):
    """dnf check-update exits 100 when updates are available."""
    fake_sudo.returncodes[("dnf", "check-update")] = 100
    ex = make_executor(fake_sudo)
    ok, _ = ex.execute_action(run_command_action(
        command=["dnf", "check-update"],
        ok_returncodes=(0, 100),
    ))
    assert ok


def test_ignore_failure_reports_success_but_says_skipped(fake_sudo):
    fake_sudo.returncodes[("ufw", "delete", "allow", "OpenSSH")] = 1
    ex = make_executor(fake_sudo)
    ok, message = ex.execute_action(run_command_action(
        command=["ufw", "delete", "allow", "OpenSSH"],
        ignore_failure=True,
    ))
    assert ok
    assert "skipped" in message


def test_fallback_command_runs_when_primary_fails(fake_sudo):
    """semanage port -a fails when the port is already defined; -m updates it."""
    primary = ["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", "2222"]
    fallback = ["semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", "2222"]
    fake_sudo.returncodes[tuple(primary)] = 1

    ex = make_executor(fake_sudo)
    ok, _ = ex.execute_action(run_command_action(
        command=primary, fallback_command=fallback
    ))
    assert ok
    assert fallback in fake_sudo.commands


# ---------------------------------------------------------------- key files


def test_append_authorized_key_writes_key_verbatim(tmp_path, fake_sudo):
    auth = tmp_path / ".ssh" / "authorized_keys"
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host"

    ex = make_executor(fake_sudo)
    ok, _ = ex.execute_action(PlannedAction(
        action_type=ActionType.APPEND_AUTHORIZED_KEY,
        description="add key",
        target=str(auth),
        public_key=key,
        requires_sudo=False,
        step_name="ssh_key",
    ))

    assert ok
    assert auth.read_text() == key + "\n"
    assert oct(auth.stat().st_mode)[-3:] == "600"
    assert oct(auth.parent.stat().st_mode)[-3:] == "700"


def test_append_authorized_key_is_idempotent(tmp_path, fake_sudo):
    auth = tmp_path / ".ssh" / "authorized_keys"
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host"
    action = PlannedAction(
        action_type=ActionType.APPEND_AUTHORIZED_KEY,
        description="add key",
        target=str(auth),
        public_key=key,
        requires_sudo=False,
        step_name="ssh_key",
    )

    ex = make_executor(fake_sudo)
    ex.execute_action(action)
    ex.execute_action(action)

    assert auth.read_text().count(key) == 1


def test_append_authorized_key_adds_newline_before_appending(tmp_path, fake_sudo):
    auth = tmp_path / ".ssh" / "authorized_keys"
    auth.parent.mkdir(parents=True)
    auth.write_text("ssh-rsa AAAAB existing")

    ex = make_executor(fake_sudo)
    ex.execute_action(PlannedAction(
        action_type=ActionType.APPEND_AUTHORIZED_KEY,
        description="add key",
        target=str(auth),
        public_key="ssh-ed25519 AAAAC new@host",
        requires_sudo=False,
        step_name="ssh_key",
    ))

    lines = auth.read_text().splitlines()
    assert lines == ["ssh-rsa AAAAB existing", "ssh-ed25519 AAAAC new@host"]


def test_append_reads_generated_public_key_from_disk(tmp_path, fake_sudo):
    key_path = tmp_path / ".ssh" / "id_ed25519"
    key_path.parent.mkdir(parents=True)
    (tmp_path / ".ssh" / "id_ed25519.pub").write_text("ssh-ed25519 GENERATED me@host\n")
    auth = tmp_path / ".ssh" / "authorized_keys"

    ex = make_executor(fake_sudo)
    ok, _ = ex.execute_action(PlannedAction(
        action_type=ActionType.APPEND_AUTHORIZED_KEY,
        description="add generated key",
        target=str(auth),
        key_path=str(key_path),
        requires_sudo=False,
        step_name="ssh_key",
    ))

    assert ok
    assert auth.read_text() == "ssh-ed25519 GENERATED me@host\n"


# ------------------------------------------------------------- verification


def test_verify_ssh_succeeds_when_active_and_listening(fake_sudo, monkeypatch):
    monkeypatch.setattr(executor_module, "listening_ports", lambda: {2222})
    fake_sudo.stdout[("systemctl", "is-active", "sshd")] = "active"

    state = WizardState()
    state.ssh_config.port = 2222
    ex = make_executor(fake_sudo, state)

    ok, message = ex.execute_action(PlannedAction(
        action_type=ActionType.VERIFY_SSH,
        description="verify",
        target="sshd",
        service="sshd",
        port=2222,
        step_name="ssh_hardening",
    ))
    assert ok
    assert "listening on port 2222" in message


def test_verify_ssh_fails_when_nothing_is_listening(fake_sudo, monkeypatch):
    monkeypatch.setattr(executor_module, "listening_ports", lambda: set())
    monkeypatch.setattr(executor_module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        executor_module.time, "monotonic", _fake_clock([0, 1, 2, 100])
    )
    fake_sudo.stdout[("systemctl", "is-active", "sshd")] = "active"

    ex = make_executor(fake_sudo)
    ok, message = ex.execute_action(PlannedAction(
        action_type=ActionType.VERIFY_SSH,
        description="verify",
        target="sshd",
        service="sshd",
        port=2222,
        step_name="ssh_hardening",
    ))
    assert not ok
    assert "nothing is listening" in message


def _fake_clock(values):
    sequence = list(values)

    def clock():
        return sequence.pop(0) if len(sequence) > 1 else sequence[0]

    return clock


# ------------------------------------------------------------------ the run


def test_execute_all_reports_failures(fake_sudo):
    """The status must not claim success when an action failed."""
    state = WizardState()
    state.actions = [
        run_command_action(command=["true"]),
        run_command_action(command=["false"], description="failing step"),
    ]
    fake_sudo.returncodes[("false",)] = 1

    ex = make_executor(fake_sudo, state)
    results = ex.execute_all()

    assert [ok for _, ok, _ in results] == [True, False]
    assert state.apply_succeeded is False
    assert any(not ok for _, ok, _ in state.apply_results)


def test_execute_all_marks_success_when_everything_passes(fake_sudo):
    state = WizardState()
    state.actions = [run_command_action(command=["true"])]

    ex = make_executor(fake_sudo, state)
    ex.execute_all()

    assert state.apply_succeeded is True
    assert state.applied is True


def test_critical_failure_aborts_before_the_firewall_runs(fake_sudo):
    """A failed sshd restart must stop the run, not lock the box down."""
    state = WizardState()
    state.ssh_service = "sshd"
    state.actions = [
        PlannedAction(
            action_type=ActionType.RESTART_SERVICE,
            description="Restart SSH daemon",
            target="sshd",
            command=["systemctl", "restart", "sshd"],
            critical=True,
            step_name="ssh_hardening",
        ),
        run_command_action(
            command=["ufw", "default", "deny", "incoming"],
            description="Set default deny incoming",
            step_name="firewall",
        ),
    ]
    fake_sudo.returncodes[("systemctl", "restart", "sshd")] = 1

    ex = make_executor(fake_sudo, state)
    ex.execute_all()

    assert ex.aborted
    assert ["ufw", "default", "deny", "incoming"] not in fake_sudo.commands


def test_critical_failure_restores_sshd_config(fake_sudo):
    state = WizardState()
    state.ssh_service = "sshd"
    state.actions = [
        PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Validate sshd_config syntax",
            target="sshd",
            command=["sshd", "-t", "-f", "/etc/ssh/sshd_config"],
            critical=True,
            step_name="ssh_hardening",
        ),
    ]
    fake_sudo.returncodes[("sshd", "-t", "-f", "/etc/ssh/sshd_config")] = 1

    ex = make_executor(fake_sudo, state)
    ex.prepare_backup_dir()
    backup_copy = f"{ex.backup_dir}/etc/ssh/sshd_config"
    fake_sudo.existing.add(backup_copy)

    ex.execute_all()

    assert ex.aborted
    assert ["cp", "-p", backup_copy, "/etc/ssh/sshd_config"] in fake_sudo.commands
    assert ["systemctl", "restart", "sshd"] in fake_sudo.commands


def test_execute_all_runs_actions_in_canonical_order(fake_sudo):
    """Revisiting a step must not push its actions to the end of the run."""
    state = WizardState()
    state.actions = [
        run_command_action(command=["firewall"], step_name="firewall"),
        run_command_action(command=["install"], step_name="welcome"),
        run_command_action(command=["harden"], step_name="ssh_hardening"),
        run_command_action(command=["key"], step_name="ssh_key"),
    ]

    ex = make_executor(fake_sudo, state)
    ex.execute_all()

    order = [c[0] for c in fake_sudo.commands if c[0] in
             {"install", "key", "harden", "firewall"}]
    assert order == ["install", "key", "harden", "firewall"]


def test_ordered_actions_is_stable_within_a_step():
    actions = [
        run_command_action(command=["b"], step_name="firewall"),
        run_command_action(command=["a"], step_name="welcome"),
        run_command_action(command=["c"], step_name="firewall"),
    ]
    assert [a.command[0] for a in ordered_actions(actions)] == ["a", "b", "c"]


def test_execute_all_raises_when_sudo_credentials_are_gone(fake_sudo):
    fake_sudo.refresh_credentials = lambda: False
    state = WizardState()
    state.actions = [run_command_action()]

    ex = make_executor(fake_sudo, state)
    with pytest.raises(executor_module.ExecutionError):
        ex.execute_all()
