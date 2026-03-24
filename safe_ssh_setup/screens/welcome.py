from __future__ import annotations

import shutil

from textual.app import ComposeResult
from textual.widgets import Label, Static

from safe_ssh_setup.distro import DistroDetectionError, detect_distro
from safe_ssh_setup.screens.base import WizardScreen


class WelcomeScreen(WizardScreen):
    step_name = "welcome"
    can_skip = False

    def compose_step(self) -> ComposeResult:
        yield Static(
            "Welcome to safe-ssh-setup",
            classes="welcome-title",
        )
        yield Static(
            "This wizard will harden your SSH server step by step.",
            classes="welcome-subtitle",
        )
        yield Static(
            "Features:\n"
            "  - SSH daemon hardening (key-only auth, strong ciphers)\n"
            "  - SSH key generation and setup\n"
            "  - Fail2Ban brute-force protection\n"
            "  - Firewall configuration\n"
            "  - Automatic security updates\n"
            "  - Port knocking (optional)\n"
            "  - Intrusion detection with rkhunter (optional)\n"
            "\n"
            "Each step can be skipped if you prefer to configure it manually.",
        )
        yield Label("", id="distro-label", classes="distro-info")
        yield Label("", id="prereq-label")

    def on_mount(self) -> None:
        self._check_system()

    def _check_system(self) -> None:
        distro_label = self.query_one("#distro-label", Label)
        prereq_label = self.query_one("#prereq-label", Label)

        # Detect distro
        try:
            distro = detect_distro()
            self.state.distro = distro.family
            self.state.distro_name = f"{distro.name} {distro.version}"
            distro_label.update(
                f"Detected: {distro.name} {distro.version} "
                f"(package manager: {distro.package_manager}, "
                f"firewall: {distro.firewall})"
            )
        except DistroDetectionError as e:
            distro_label.update(f"Error: {e}")
            self._distro_error = str(e)
            return

        # Check prerequisites
        checks = []
        if shutil.which("sshd") or shutil.which("ssh"):
            checks.append("[OK] OpenSSH server found")
        else:
            checks.append("[!!] OpenSSH server not found - will be installed")

        if shutil.which("systemctl"):
            checks.append("[OK] systemd available")
        else:
            checks.append("[!!] systemd not found - required for service management")

        prereq_label.update("\n".join(checks))
        self._distro_error = None

    def validate_step(self) -> str | None:
        if hasattr(self, "_distro_error") and self._distro_error:
            return self._distro_error
        if self.state.distro is None:
            return "Could not detect your Linux distribution."
        return None
