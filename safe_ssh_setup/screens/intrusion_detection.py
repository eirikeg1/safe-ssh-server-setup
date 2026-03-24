from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, Static, Switch

from safe_ssh_setup.distro import PackageManager, detect_distro
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen


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
        yield Switch(value=False, id="enable-rkhunter")

        yield Static(
            "\nWhat rkhunter does:\n"
            "  - Scans for known rootkits and malware\n"
            "  - Checks system binaries for modifications\n"
            "  - Monitors for suspicious file permissions\n"
            "  - Sets up a daily cron job for automated scanning",
            classes="section-description",
        )

    def save_state(self) -> None:
        enabled = self.query_one("#enable-rkhunter", Switch).value
        self.state.intrusion_detection.enabled = enabled

        self.clear_step_actions()

        if not enabled:
            return

        distro = detect_distro()
        pm = PackageManager(distro)

        # Install rkhunter
        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description="Install rkhunter",
            target="rkhunter",
            command=pm.install_command(["rkhunter"]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Update rkhunter database
        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Update rkhunter properties database",
            target="rkhunter",
            command="rkhunter --update && rkhunter --propupd",
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Set up daily cron
        cron_content = (
            "#!/bin/bash\n"
            "# Installed by safe-ssh-setup\n"
            "/usr/bin/rkhunter --check --cronjob --report-warnings-only\n"
        )
        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Create daily rkhunter cron job",
            target="/etc/cron.daily/rkhunter-check",
            content=cron_content,
            original_content="",
            permissions="755",
            owner="root:root",
            requires_sudo=True,
            step_name=self.step_name,
        ))
