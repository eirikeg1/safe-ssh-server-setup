from __future__ import annotations

import subprocess


class SudoHelper:
    @staticmethod
    def check_sudo_available() -> bool:
        """Check if the user already has cached sudo credentials."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def prompt_sudo() -> bool:
        """Prompt the user for sudo credentials. Returns True on success."""
        try:
            result = subprocess.run(["sudo", "-v"], timeout=60)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def refresh_credentials() -> None:
        """Refresh the sudo credential cache."""
        subprocess.run(
            ["sudo", "-v"],
            capture_output=True,
            timeout=10,
        )

    @staticmethod
    def run(
        command: str,
        check: bool = True,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        """Run a command with sudo."""
        return subprocess.run(
            ["sudo", "bash", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    @staticmethod
    def run_no_sudo(
        command: str,
        check: bool = True,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        """Run a command without sudo."""
        return subprocess.run(
            ["bash", "-c", command],
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
    ) -> None:
        """Write content to a file using sudo."""
        subprocess.run(
            ["sudo", "tee", path],
            input=content,
            capture_output=True,
            text=True,
            check=True,
        )
        subprocess.run(["sudo", "chmod", mode, path], check=True)
        subprocess.run(["sudo", "chown", owner, path], check=True)

    @staticmethod
    def read_file(path: str) -> str | None:
        """Read a file, using sudo if needed. Returns None if file doesn't exist."""
        try:
            result = subprocess.run(
                ["sudo", "cat", path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except subprocess.TimeoutExpired:
            return None
