from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.widgets import Label, Static, Switch

from safe_ssh_setup.distro import PackageManager
from safe_ssh_setup.models import ActionType, DistroFamily, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen

# Debian's rkhunter package ships its own /etc/cron.daily/rkhunter; installing
# a second one would run two full scans a day.
DISTRO_CRON = "/etc/cron.daily/rkhunter"
OUR_CRON = "/etc/cron.daily/rkhunter-safe-ssh-setup"


class IntrusionDetectionScreen(WizardScreen):
    step_name = "intrusion_detection"

    def compose_step(self) -> ComposeResult:
        yield Static("Intrusion Detection", classes="section-header")
        yield Static(
            "rkhunter (Rootkit Hunter) scans your system for rootkits, "
            "backdoors, and local exploits. It compares file hashes "
            "against known-good values and checks for suspicious activity.",
            classes="section-description",
        )

        yield Label("Enable rkhunter")
        yield Switch(value=self.state.intrusion_detection.enabled, id="enable-rkhunter")

        yield Static(
            "\nWhat rkhunter does:\n"
            "  - Scans for known rootkits and malware\n"
            "  - Checks system binaries for modifications\n"
            "  - Monitors for suspicious file permissions\n"
            "  - Runs a daily scan via cron",
            classes="section-description",
        )

    def skip_step(self) -> None:
        super().skip_step()
        self.state.intrusion_detection.enabled = False

    def save_state(self) -> None:
        enabled = self.query_one("#enable-rkhunter", Switch).value
        self.state.intrusion_detection.enabled = enabled

        self.clear_step_actions()
        if not enabled:
            return

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

        packages = ["rkhunter"]
        # /etc/cron.daily only runs if a cron implementation is installed;
        # Fedora minimal images ship without cronie.
        if distro.family == DistroFamily.RHEL:
            packages.append("cron")

        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description="Install rkhunter",
            target="rkhunter",
            command=pm.install_command(packages),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Mirror updates are frequently unavailable; that must not fail the run.
        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Update rkhunter data files",
            target="rkhunter",
            command=["rkhunter", "--update"],
            ignore_failure=True,
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Record baseline file properties",
            target="rkhunter",
            command=["rkhunter", "--propupd"],
            requires_sudo=True,
            step_name=self.step_name,
        ))

        if Path(DISTRO_CRON).exists():
            return

        cron_content = (
            "#!/bin/bash\n"
            "# Installed by safe-ssh-setup\n"
            "/usr/bin/rkhunter --check --cronjob --report-warnings-only\n"
        )
        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Create daily rkhunter cron job",
            target=OUR_CRON,
            content=cron_content,
            original_content="",
            permissions="0755",
            owner="root:root",
            requires_sudo=True,
            step_name=self.step_name,
        ))
