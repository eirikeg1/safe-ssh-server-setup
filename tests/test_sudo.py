"""Sudo helper tests.

The original helpers passed command *strings* to `bash -c` and captured output
without `-n`, so an expired credential cache produced an invisible password
prompt that blocked until the timeout expired.
"""

from __future__ import annotations

import subprocess

import pytest

from safe_ssh_setup import sudo as sudo_module
from safe_ssh_setup.sudo import SudoHelper, format_command


@pytest.fixture
def recorded(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_run_never_spawns_a_shell(recorded):
    SudoHelper.run(["ufw", "allow", "2222/tcp"])
    argv, kwargs = recorded[0]
    assert argv == ["sudo", "-n", "--", "ufw", "allow", "2222/tcp"]
    assert "shell" not in kwargs or kwargs["shell"] is False
    assert "bash" not in argv


def test_run_is_non_interactive(recorded):
    """Without -n a captured password prompt hangs until the timeout."""
    SudoHelper.run(["true"])
    argv, _ = recorded[0]
    assert "-n" in argv


def test_run_passes_a_timeout(recorded):
    SudoHelper.run(["true"])
    _, kwargs = recorded[0]
    assert kwargs.get("timeout")


def test_arguments_with_metacharacters_stay_a_single_argument(recorded):
    nasty = 'ssh-ed25519 AAAA $(touch /tmp/pwned); rm -rf /'
    SudoHelper.run(["echo", nasty])
    argv, _ = recorded[0]
    assert argv[-1] == nasty
    assert len(argv) == 5


def test_run_as_user_drops_privileges_when_root(monkeypatch, recorded):
    monkeypatch.setattr(sudo_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sudo_module, "target_user", lambda: "eirik")

    SudoHelper.run_as_user(["ssh-keygen", "-t", "ed25519"])
    argv, _ = recorded[0]
    assert argv[:4] == ["runuser", "-u", "eirik", "--"]


def test_run_as_user_is_direct_when_not_root(monkeypatch, recorded):
    monkeypatch.setattr(sudo_module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sudo_module, "target_user", lambda: "eirik")

    SudoHelper.run_as_user(["ssh-keygen"])
    argv, _ = recorded[0]
    assert argv == ["ssh-keygen"]


def test_write_file_applies_mode_before_moving_into_place(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    SudoHelper.write_file("/etc/ssh/sshd_config", "Port 22\n", mode="0600")

    flat = [" ".join(c) for c in calls]
    chmod = next(i for i, c in enumerate(flat) if "chmod" in c)
    move = next(i for i, c in enumerate(flat) if " mv " in f" {c} ")
    assert chmod < move, "final path must never exist with looser permissions"
    assert any("tee" in c and ".tmp" in c for c in flat)


def test_write_file_sends_content_via_stdin(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        if "tee" in argv:
            captured["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    SudoHelper.write_file("/etc/x", "line1\n$(id)\n")
    assert captured["input"] == "line1\n$(id)\n"


def test_format_command_is_display_only():
    assert format_command(["ufw", "allow", "2222/tcp"]) == "ufw allow 2222/tcp"
    assert format_command(["echo", "a b"]) == "echo 'a b'"
    assert format_command(None) == ""
