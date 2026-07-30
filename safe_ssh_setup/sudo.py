"""Privilege escalation helpers.

Every command is passed as an argv list and executed without a shell. Nothing
here interpolates caller data into a command string, so values that reach these
helpers (public keys, paths, ports) cannot be interpreted as shell syntax.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading

from safe_ssh_setup.system import target_user

DEFAULT_TIMEOUT = 300
KEEPALIVE_INTERVAL = 60


class SudoUnavailableError(RuntimeError):
    """Raised when sudo credentials are not (or no longer) available."""


def format_command(argv: list[str] | None) -> str:
    """Render argv for display. Never fed back into a shell."""
    if not argv:
        return ""
    return shlex.join(argv)


class SudoHelper:
    @staticmethod
    def check_sudo_available() -> bool:
        """Whether the user already has cached sudo credentials."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    @staticmethod
    def prompt_sudo() -> bool:
        """Prompt for sudo credentials on the real terminal."""
        try:
            result = subprocess.run(["sudo", "-v"], timeout=120)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    @staticmethod
    def refresh_credentials() -> bool:
        """Refresh the credential cache without ever prompting."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "-v"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    @staticmethod
    def start_keepalive() -> threading.Event:
        """Refresh sudo credentials periodically until the returned event is set."""
        stop = threading.Event()

        def _keepalive() -> None:
            while not stop.wait(KEEPALIVE_INTERVAL):
                SudoHelper.refresh_credentials()

        threading.Thread(target=_keepalive, daemon=True).start()
        return stop

    @staticmethod
    def run(
        argv: list[str],
        check: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> subprocess.CompletedProcess[str]:
        """Run argv under sudo, non-interactively.

        ``-n`` matters: with output captured, an interactive password prompt
        would be invisible and the call would block until it timed out.
        """
        return subprocess.run(
            ["sudo", "-n", "--", *argv],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    @staticmethod
    def run_as_user(
        argv: list[str],
        check: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> subprocess.CompletedProcess[str]:
        """Run argv as the target (non-root) user.

        When the wizard itself was started with sudo, this drops back down to
        SUDO_USER so files land in the right home with the right owner.
        """
        user = target_user()
        if os.geteuid() == 0 and user != "root":
            argv = ["runuser", "-u", user, "--", *argv]
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    @staticmethod
    def write_file(
        path: str,
        content: str,
        mode: str = "0644",
        owner: str = "root:root",
        timeout: int = 60,
    ) -> None:
        """Write a root-owned file atomically with the final mode applied first.

        Content goes in via stdin, so it is never parsed as a command. The
        temporary file is chmod/chown'd before being moved into place, so the
        final path never exists with looser permissions than intended.
        """
        tmp_path = f"{path}.safe-ssh-setup.tmp"
        parent = os.path.dirname(path) or "/"

        mkdir = SudoHelper.run(["mkdir", "-p", parent], timeout=timeout)
        if mkdir.returncode != 0:
            raise SudoUnavailableError(
                f"Could not create {parent}: {mkdir.stderr.strip()}"
            )

        result = subprocess.run(
            ["sudo", "-n", "--", "tee", tmp_path],
            input=content,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise SudoUnavailableError(
                f"Could not write {tmp_path}: {result.stderr.strip()}"
            )

        for argv in (
            ["chmod", mode, tmp_path],
            ["chown", owner, tmp_path],
            ["mv", "-f", tmp_path, path],
        ):
            step = SudoHelper.run(argv, timeout=timeout)
            if step.returncode != 0:
                SudoHelper.run(["rm", "-f", tmp_path], timeout=timeout)
                raise SudoUnavailableError(
                    f"{argv[0]} failed for {path}: {step.stderr.strip()}"
                )

    @staticmethod
    def read_file(path: str) -> str | None:
        """Read a possibly root-only file. None when absent or unreadable."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "--", "cat", path],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if result.returncode == 0:
            return result.stdout
        return None

    @staticmethod
    def file_exists(path: str) -> bool:
        result = SudoHelper.run(["test", "-e", path], timeout=15)
        return result.returncode == 0
