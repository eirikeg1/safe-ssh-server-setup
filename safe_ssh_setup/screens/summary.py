from __future__ import annotations

import os

from textual.app import ComposeResult
from textual.widgets import Static

from safe_ssh_setup.screens.base import WizardScreen


class SummaryScreen(WizardScreen):
    step_name = "summary"
    can_skip = False
    next_label = "Finish"

    def compose_step(self) -> ComposeResult:
        yield Static("Setup Complete!", classes="welcome-title")

        # Connection info
        port = self.state.ssh_config.port
        user = os.environ.get("USER", "your_user")

        yield Static("Connection", classes="section-header")
        yield Static(
            f"  ssh -p {port} {user}@your-server-ip",
            classes="summary-section",
        )

        # What was configured
        yield Static("What was configured", classes="section-header")

        items = []
        items.append(f"  SSH port: {port}")
        items.append(
            f"  Authentication: {'Key-only' if not self.state.ssh_config.password_authentication else 'Password + Key'}"
        )
        items.append(f"  Root login: {self.state.ssh_config.permit_root_login}")

        if self.state.ssh_key.generate_key:
            key_path = self.state.ssh_key.key_path or "~/.ssh/id_ed25519"
            items.append(f"  SSH key: generated at {key_path}")
        elif self.state.ssh_key.setup_authorized_keys:
            items.append("  SSH key: client public key added to authorized_keys")

        if self.state.fail2ban.enabled:
            items.append(
                f"  Fail2Ban: enabled (ban after {self.state.fail2ban.max_retry} "
                f"failures, {self.state.fail2ban.ban_time}s ban)"
            )

        if self.state.firewall.enabled:
            items.append(
                f"  Firewall: enabled"
                f"{' with rate limiting' if self.state.firewall.rate_limiting else ''}"
            )

        if self.state.auto_updates.enabled:
            items.append("  Auto updates: enabled")

        if self.state.port_knocking.enabled:
            seq = " ".join(str(p) for p in self.state.port_knocking.sequence)
            items.append(f"  Port knocking: enabled (sequence: {seq})")

        if self.state.intrusion_detection.enabled:
            items.append("  Intrusion detection: rkhunter enabled")

        yield Static("\n".join(items), classes="summary-section")

        # Not configured
        skipped = []
        if not self.state.fail2ban.enabled:
            skipped.append("  Fail2Ban (brute-force protection)")
        if not self.state.firewall.enabled:
            skipped.append("  Firewall")
        if not self.state.auto_updates.enabled:
            skipped.append("  Automatic security updates")
        if not self.state.port_knocking.enabled:
            skipped.append("  Port knocking")
        if not self.state.intrusion_detection.enabled:
            skipped.append("  Intrusion detection (rkhunter)")

        if skipped:
            yield Static("Not configured", classes="section-header")
            yield Static("\n".join(skipped), classes="summary-section")

        # Backup info
        if self.state.backup_dir:
            yield Static("Backup & Rollback", classes="section-header")
            yield Static(
                f"  Backup directory: {self.state.backup_dir}\n"
                f"  Rollback command:\n"
                f"    sudo bash {self.state.backup_dir}/rollback.sh",
                classes="summary-section",
            )

        # Port knocking usage
        if self.state.port_knocking.enabled:
            seq = " ".join(str(p) for p in self.state.port_knocking.sequence)
            yield Static("Port Knocking Usage", classes="section-header")
            yield Static(
                f"  knock -v your-server-ip {seq}\n"
                f"  ssh -p {port} {user}@your-server-ip",
                classes="summary-section",
            )

        # Warning
        yield Static(
            "IMPORTANT: Test SSH access in a NEW terminal before "
            "closing this session! If you get locked out, use the "
            "rollback script above to restore your original configuration.",
            classes="summary-warning",
        )

    def on_button_pressed(self, event) -> None:
        if hasattr(event, "button") and getattr(event.button, "id", None) == "btn-next":
            self.app.exit()
        else:
            super().on_button_pressed(event)
