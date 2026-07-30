from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.widgets import Label, Static, Switch

from safe_ssh_setup.distro import PackageManager, is_dnf5
from safe_ssh_setup.models import ActionType, DistroFamily, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.screens.ssh_hardening import build_environment
from safe_ssh_setup.sudo import SudoHelper

# Written as a drop-in instead of overwriting the 50unattended-upgrades
# conffile shipped by the package.
APT_CONFIG = "/etc/apt/apt.conf.d/52safe-ssh-setup"
APT_PERIODIC = "/etc/apt/apt.conf.d/20auto-upgrades"
DNF_CONFIG = "/etc/dnf/automatic.conf"
DNF5_CONFIG = "/etc/dnf/dnf5-plugins/automatic.conf"


class AutoUpdatesScreen(WizardScreen):
    step_name = "auto_updates"

    def compose_step(self) -> ComposeResult:
        distro = self.state.distro_info

        yield Static("Automatic Security Updates", classes="section-header")

        if not distro:
            yield Static("Distribution not detected; go back to the Welcome step.")
            return

        yield Static(
            f"Automatically install security updates using "
            f"{distro.auto_updates_package}. This keeps the server patched "
            "without manual intervention.",
            classes="section-description",
        )

        yield Label("Enable automatic security updates")
        yield Switch(value=self.state.auto_updates.enabled, id="enable-updates")

        yield Static(
            f"\nPackage: {distro.auto_updates_package}\n"
            f"Timer:   {distro.auto_updates_timer}",
            classes="section-description",
        )

    def skip_step(self) -> None:
        super().skip_step()
        self.state.auto_updates.enabled = False

    def save_state(self) -> None:
        enabled = self.query_one("#enable-updates", Switch).value
        self.state.auto_updates.enabled = enabled

        self.clear_step_actions()
        if not enabled:
            return

        distro = self.state.distro_info
        if not distro:
            return

        pm = PackageManager(distro)
        env = build_environment()
        timestamp = datetime.now().isoformat(timespec="seconds")

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
            description=f"Install {distro.auto_updates_package}",
            target=distro.auto_updates_package,
            command=pm.install_command([distro.auto_updates_package]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        if distro.family == DistroFamily.DEBIAN:
            self._plan_debian(env, timestamp)
        else:
            self._plan_rhel(env, timestamp)

        self.state.actions.append(PlannedAction(
            action_type=ActionType.ENABLE_SERVICE,
            description=f"Enable {distro.auto_updates_timer}",
            target=distro.auto_updates_timer,
            command=["systemctl", "enable", "--now", distro.auto_updates_timer],
            requires_sudo=True,
            step_name=self.step_name,
        ))

    def _plan_debian(self, env, timestamp: str) -> None:
        content = env.get_template("unattended_upgrades.j2").render(
            timestamp=timestamp
        )
        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Configure unattended-upgrades",
            target=APT_CONFIG,
            content=content,
            original_content=SudoHelper.read_file(APT_CONFIG) or "",
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Without the periodic settings, unattended-upgrades is configured but
        # never actually runs.
        periodic = env.get_template("apt_auto_upgrades.j2").render(
            timestamp=timestamp
        )
        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Enable periodic unattended-upgrades runs",
            target=APT_PERIODIC,
            content=periodic,
            original_content=SudoHelper.read_file(APT_PERIODIC) or "",
            requires_sudo=True,
            step_name=self.step_name,
        ))

    def _plan_rhel(self, env, timestamp: str) -> None:
        content = env.get_template("dnf_automatic.j2").render(timestamp=timestamp)

        targets = [DNF_CONFIG]
        # dnf5 reads its own plugin config path in addition to the legacy one.
        if is_dnf5() or Path(DNF5_CONFIG).parent.exists():
            targets.append(DNF5_CONFIG)

        for target in targets:
            self.state.actions.append(PlannedAction(
                action_type=ActionType.WRITE_FILE,
                description=f"Configure dnf-automatic ({target})",
                target=target,
                content=content,
                original_content=SudoHelper.read_file(target) or "",
                requires_sudo=True,
                step_name=self.step_name,
            ))
