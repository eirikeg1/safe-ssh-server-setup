from __future__ import annotations

from datetime import datetime

from jinja2 import Environment, PackageLoader
from textual.app import ComposeResult
from textual.widgets import Input, Label, Static, Switch

from safe_ssh_setup.distro import detect_distro, PackageManager
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.sudo import SudoHelper


class Fail2BanScreen(WizardScreen):
    step_name = "fail2ban"

    def compose_step(self) -> ComposeResult:
        yield Static("Fail2Ban Configuration", classes="section-header")
        yield Static(
            "Fail2Ban monitors SSH login attempts and bans IPs that "
            "fail too many times. Essential for preventing brute-force attacks.",
            classes="section-description",
        )

        yield Label("Enable Fail2Ban")
        yield Switch(value=True, id="enable-f2b")

        yield Static("Settings", classes="section-header")

        yield Label("Max retry attempts before ban:")
        yield Input(value="5", id="max-retry", type="integer")

        yield Label("Find time (seconds) - window for counting failures:")
        yield Input(value="600", id="find-time", type="integer")

        yield Label("Ban time (seconds) - how long an IP is banned:")
        yield Input(value="3600", id="ban-time", type="integer")

    def validate_step(self) -> str | None:
        if not self.query_one("#enable-f2b", Switch).value:
            return None
        try:
            mr = int(self.query_one("#max-retry", Input).value or "0")
            ft = int(self.query_one("#find-time", Input).value or "0")
            bt = int(self.query_one("#ban-time", Input).value or "0")
        except ValueError:
            return "All values must be valid numbers."
        if mr < 1:
            return "Max retry must be at least 1."
        if ft < 1:
            return "Find time must be at least 1 second."
        if bt < 1:
            return "Ban time must be at least 1 second."
        return None

    def save_state(self) -> None:
        enabled = self.query_one("#enable-f2b", Switch).value
        self.state.fail2ban.enabled = enabled

        if not enabled:
            self.clear_step_actions()
            return

        self.state.fail2ban.max_retry = int(
            self.query_one("#max-retry", Input).value or "5"
        )
        self.state.fail2ban.find_time = int(
            self.query_one("#find-time", Input).value or "600"
        )
        self.state.fail2ban.ban_time = int(
            self.query_one("#ban-time", Input).value or "3600"
        )

        self.clear_step_actions()

        # Install fail2ban
        distro = detect_distro()
        pm = PackageManager(distro)

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Update package lists",
            target="packages",
            command=pm.update_command(),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description="Install fail2ban",
            target="fail2ban",
            command=pm.install_command(["fail2ban"]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Generate jail.local
        env = Environment(
            loader=PackageLoader("safe_ssh_setup", "templates"),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("fail2ban_jail.j2")
        content = template.render(
            f2b=self.state.fail2ban,
            ssh_port=self.state.ssh_config.port,
            ssh_service=self.state.ssh_service,
            timestamp=datetime.now().isoformat(),
        )

        original = SudoHelper.read_file("/etc/fail2ban/jail.local") or ""

        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Write fail2ban jail configuration",
            target="/etc/fail2ban/jail.local",
            content=content,
            original_content=original,
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.ENABLE_SERVICE,
            description="Enable and start fail2ban",
            target="fail2ban",
            command="systemctl enable --now fail2ban",
            requires_sudo=True,
            step_name=self.step_name,
        ))
