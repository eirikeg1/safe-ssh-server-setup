from __future__ import annotations

from datetime import datetime

from textual.app import ComposeResult
from textual.widgets import Input, Label, Static, Switch

from safe_ssh_setup.distro import PackageManager
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.screens.ssh_hardening import build_environment
from safe_ssh_setup.sudo import SudoHelper
from safe_ssh_setup.validation import ValidationError, validate_positive


class Fail2BanScreen(WizardScreen):
    step_name = "fail2ban"

    def compose_step(self) -> ComposeResult:
        cfg = self.state.fail2ban

        yield Static("Fail2Ban Configuration", classes="section-header")
        yield Static(
            "Fail2Ban monitors SSH login attempts and bans IPs that "
            "fail too many times. Essential for preventing brute-force attacks.",
            classes="section-description",
        )

        yield Label("Enable Fail2Ban")
        yield Switch(value=cfg.enabled, id="enable-f2b")

        yield Static("Settings", classes="section-header")

        yield Label("Max retry attempts before ban:")
        yield Input(value=str(cfg.max_retry), id="max-retry", type="integer")

        yield Label("Find time (seconds) - window for counting failures:")
        yield Input(value=str(cfg.find_time), id="find-time", type="integer")

        yield Label("Ban time (seconds) - how long an IP is banned:")
        yield Input(value=str(cfg.ban_time), id="ban-time", type="integer")

        distro = self.state.distro_info
        if distro:
            yield Static(
                f"\nBan backend: {distro.fail2ban_banaction} "
                f"(matched to {distro.firewall})",
                classes="section-description",
            )

    def validate_step(self) -> str | None:
        if not self.query_one("#enable-f2b", Switch).value:
            return None
        try:
            validate_positive(self.query_one("#max-retry", Input).value, "Max retry")
            validate_positive(self.query_one("#find-time", Input).value, "Find time")
            validate_positive(self.query_one("#ban-time", Input).value, "Ban time")
        except ValidationError as e:
            return str(e)
        return None

    def skip_step(self) -> None:
        super().skip_step()
        self.state.fail2ban.enabled = False

    def save_state(self) -> None:
        enabled = self.query_one("#enable-f2b", Switch).value
        self.state.fail2ban.enabled = enabled

        self.clear_step_actions()
        if not enabled:
            return

        self.state.fail2ban.max_retry = validate_positive(
            self.query_one("#max-retry", Input).value, "Max retry"
        )
        self.state.fail2ban.find_time = validate_positive(
            self.query_one("#find-time", Input).value, "Find time"
        )
        self.state.fail2ban.ban_time = validate_positive(
            self.query_one("#ban-time", Input).value, "Ban time"
        )

        distro = self.state.distro_info
        if not distro:
            return
        pm = PackageManager(distro)

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
            description="Install fail2ban",
            target="fail2ban",
            command=pm.install_command(["fail2ban"]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        template = build_environment().get_template("fail2ban_jail.j2")
        content = template.render(
            f2b=self.state.fail2ban,
            ssh_port=self.state.ssh_config.port,
            # Ban action and backend follow the distro, not a hardcoded guess:
            # forcing iptables on a firewalld system breaks banning.
            banaction=distro.fail2ban_banaction,
            banaction_allports=(
                "firewallcmd-ipset" if distro.fail2ban_banaction.startswith("firewallcmd")
                else "iptables-allports"
            ),
            backend=distro.fail2ban_backend,
            timestamp=datetime.now().isoformat(timespec="seconds"),
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
            command=["systemctl", "enable", "--now", "fail2ban"],
            requires_sudo=True,
            step_name=self.step_name,
        ))
