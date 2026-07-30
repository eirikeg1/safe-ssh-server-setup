from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, Static

from safe_ssh_setup.distro import DistroDetectionError, PackageManager, detect_distro
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.system import (
    configured_sshd_port,
    is_ssh_session,
    selinux_enabled,
    sshd_binary_installed,
    systemd_available,
    target_user,
)


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
            "  - SSH key setup\n"
            "  - Fail2Ban brute-force protection\n"
            "  - Firewall configuration\n"
            "  - Automatic security updates\n"
            "  - Port knocking (optional)\n"
            "  - Intrusion detection with rkhunter (optional)\n"
            "\n"
            "Nothing is changed until you confirm the Review step. Every file "
            "the wizard touches is backed up first, with a rollback script.",
        )
        yield Label("", id="distro-label", classes="distro-info")
        yield Label("", id="prereq-label")
        yield Label("", id="session-label", classes="section-description")

    def on_mount(self) -> None:
        self._check_system()

    def _check_system(self) -> None:
        distro_label = self.query_one("#distro-label", Label)
        prereq_label = self.query_one("#prereq-label", Label)
        session_label = self.query_one("#session-label", Label)

        self._distro_error: str | None = None
        self._sshd_missing = False

        try:
            distro = detect_distro()
        except DistroDetectionError as e:
            distro_label.update(f"Error: {e}")
            self._distro_error = str(e)
            self.state.distro_info = None
            return

        self.state.distro = distro.family
        self.state.distro_info = distro
        self.state.distro_name = f"{distro.name} {distro.version}"
        self.state.ssh_service = distro.ssh_service
        self.state.existing_ssh_port = configured_sshd_port()
        self.state.ssh_config.port = self.state.ssh_config.port or 22

        distro_label.update(
            f"Detected: {distro.name} {distro.version} "
            f"(package manager: {distro.package_manager}, "
            f"firewall: {distro.firewall})"
        )

        checks = []
        # Check for the sshd binary directly: the ssh *client* is present on
        # nearly every system and says nothing about the server, and /usr/sbin
        # is not on a non-root user's PATH on Debian.
        if sshd_binary_installed():
            checks.append("[OK] OpenSSH server found")
        else:
            checks.append("[!!] OpenSSH server not found - will be installed")
            self._sshd_missing = True

        if systemd_available():
            checks.append("[OK] systemd available")
        else:
            checks.append("[!!] systemd not found - required for service management")

        checks.append(f"[OK] Configuring SSH access for user: {target_user()}")
        checks.append(f"[OK] sshd currently on port {self.state.existing_ssh_port}")

        if selinux_enabled():
            checks.append("[OK] SELinux active - ports will be labelled")

        prereq_label.update("\n".join(checks))

        if is_ssh_session():
            session_label.update(
                "You are connected over SSH. Keep this session open until you "
                "have confirmed a new connection works — it is your way back "
                "in if something goes wrong."
            )

    def validate_step(self) -> str | None:
        if getattr(self, "_distro_error", None):
            return self._distro_error
        if self.state.distro is None:
            return "Could not detect your Linux distribution."
        if not systemd_available():
            return "systemd is required but was not detected on this system."
        return None

    def save_state(self) -> None:
        self.clear_step_actions()

        if not self._sshd_missing or not self.state.distro_info:
            return

        pm = PackageManager(self.state.distro_info)

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Update package lists",
            target="packages",
            command=pm.update_command(),
            ok_returncodes=pm.update_ok_returncodes(),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description="Install OpenSSH server",
            target="openssh-server",
            command=pm.install_command(["openssh-server"]),
            requires_sudo=True,
            critical=True,
            step_name=self.step_name,
        ))
