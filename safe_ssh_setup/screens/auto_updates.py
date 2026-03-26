from __future__ import annotations

from datetime import datetime

from jinja2 import Environment, PackageLoader
from textual.app import ComposeResult
from textual.widgets import Label, Static, Switch

from safe_ssh_setup.distro import PackageManager, detect_distro
from safe_ssh_setup.models import ActionType, DistroFamily, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.sudo import SudoHelper


class AutoUpdatesScreen(WizardScreen):
    step_name = "auto_updates"

    def compose_step(self) -> ComposeResult:
        yield Static("Automatic Security Updates", classes="section-header")

        distro = detect_distro()
        pkg_name = distro.auto_updates_package

        yield Static(
            f"Automatically install security updates using {pkg_name}. "
            "This ensures your server stays patched without manual intervention.",
            classes="section-description",
        )

        yield Label("Enable automatic security updates")
        yield Switch(value=True, id="enable-updates")

        yield Static(
            f"\nPackage: {pkg_name}",
            classes="section-description",
        )

    def save_state(self) -> None:
        enabled = self.query_one("#enable-updates", Switch).value
        self.state.auto_updates.enabled = enabled

        self.clear_step_actions()

        if not enabled:
            return

        distro = detect_distro()
        pm = PackageManager(distro)

        # Update package lists
        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Update package lists",
            target="packages",
            command=pm.update_command(),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Install auto-updates package
        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description=f"Install {distro.auto_updates_package}",
            target=distro.auto_updates_package,
            command=pm.install_command([distro.auto_updates_package]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        env = Environment(
            loader=PackageLoader("safe_ssh_setup", "templates"),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        if distro.family == DistroFamily.DEBIAN:
            template = env.get_template("unattended_upgrades.j2")
            content = template.render(timestamp=datetime.now().isoformat())
            target = "/etc/apt/apt.conf.d/50unattended-upgrades"

            original = SudoHelper.read_file(target) or ""

            self.state.actions.append(PlannedAction(
                action_type=ActionType.WRITE_FILE,
                description="Configure unattended-upgrades",
                target=target,
                content=content,
                original_content=original,
                requires_sudo=True,
                step_name=self.step_name,
            ))

            # Enable the apt timer
            self.state.actions.append(PlannedAction(
                action_type=ActionType.ENABLE_SERVICE,
                description="Enable unattended-upgrades timer",
                target="apt-daily-upgrade.timer",
                command="systemctl enable --now apt-daily-upgrade.timer",
                requires_sudo=True,
                step_name=self.step_name,
            ))
        else:
            template = env.get_template("dnf_automatic.j2")
            content = template.render(timestamp=datetime.now().isoformat())
            target = "/etc/dnf/automatic.conf"

            original = SudoHelper.read_file(target) or ""

            self.state.actions.append(PlannedAction(
                action_type=ActionType.WRITE_FILE,
                description="Configure dnf-automatic",
                target=target,
                content=content,
                original_content=original,
                requires_sudo=True,
                step_name=self.step_name,
            ))

            self.state.actions.append(PlannedAction(
                action_type=ActionType.ENABLE_SERVICE,
                description="Enable dnf-automatic timer",
                target="dnf-automatic-install.timer",
                command="systemctl enable --now dnf-automatic-install.timer",
                requires_sudo=True,
                step_name=self.step_name,
            ))
