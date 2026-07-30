from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Button, Static

from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.system import target_user


class SummaryScreen(WizardScreen):
    step_name = "summary"
    can_skip = False
    can_go_back = False
    next_label = "Finish"

    def compose_step(self) -> ComposeResult:
        port = self.state.ssh_config.port
        user = target_user()

        failures = [
            (description, message)
            for description, ok, message in self.state.apply_results
            if not ok
        ]

        if failures:
            yield Static("Setup Completed With Errors", classes="welcome-title")
            yield Static(
                "These actions failed. Do not close your current SSH session "
                "until you have confirmed you can still connect:\n\n"
                + "\n".join(f"  - {d}: {m}" for d, m in failures),
                classes="summary-warning",
            )
        else:
            yield Static("Setup Complete!", classes="welcome-title")

        yield Static("Connection", classes="section-header")
        connection = f"  ssh -p {port} {user}@your-server-ip"
        if self.state.port_knocking.enabled:
            sequence = " ".join(str(p) for p in self.state.port_knocking.sequence)
            connection = (
                f"  knock -v your-server-ip {sequence}\n"
                f"  ssh -p {port} {user}@your-server-ip"
            )
        yield Static(connection, classes="summary-section")

        yield Static("What was configured", classes="section-header")

        items = [
            f"  SSH port: {port}",
            "  Authentication: "
            + (
                "Key-only"
                if not self.state.ssh_config.password_authentication
                else "Password + Key"
            ),
            f"  Root login: {self.state.ssh_config.permit_root_login}",
        ]

        if self.state.ssh_key.generate_key:
            key_path = self.state.ssh_key.key_path or "~/.ssh/id_ed25519"
            items.append(f"  SSH key: generated at {key_path}")
        elif self.state.ssh_key.public_key:
            items.append("  SSH key: client public key added to authorized_keys")

        if self.state.fail2ban.enabled:
            items.append(
                f"  Fail2Ban: enabled (ban after {self.state.fail2ban.max_retry} "
                f"failures, {self.state.fail2ban.ban_time}s ban)"
            )
        if self.state.firewall.enabled:
            detail = "enabled"
            if self.state.firewall.rate_limiting:
                detail += " with rate limiting"
            if self.state.firewall.default_deny:
                detail += ", default deny incoming"
            items.append(f"  Firewall: {detail}")
        if self.state.auto_updates.enabled:
            items.append("  Auto updates: enabled")
        if self.state.port_knocking.enabled:
            sequence = " ".join(str(p) for p in self.state.port_knocking.sequence)
            items.append(f"  Port knocking: enabled (sequence: {sequence})")
        if self.state.intrusion_detection.enabled:
            items.append("  Intrusion detection: rkhunter enabled")

        yield Static("\n".join(items), classes="summary-section")

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

        if self.state.ssh_key.generate_key and self.state.ssh_key.key_path:
            yield Static("Move your private key off this server", classes="section-header")
            yield Static(
                "The private key was generated here and has no passphrase. "
                "Copy it to your client, then delete it from the server:\n"
                f"    (on your client) scp -P {port} "
                f"{user}@your-server-ip:{self.state.ssh_key.key_path} ~/.ssh/\n"
                f"    (on this server) shred -u {self.state.ssh_key.key_path}",
                classes="summary-warning",
            )

        if self.state.backup_dir:
            yield Static("Backup & Rollback", classes="section-header")
            yield Static(
                f"  Backup directory: {self.state.backup_dir}\n"
                f"  Rollback command:\n"
                f"    sudo bash {self.state.backup_dir}/rollback.sh\n"
                "\n"
                "  Rollback restores modified files and removes files this run "
                "created.\n"
                "  Firewall rules, enabled services and installed packages are "
                "not reverted.",
                classes="summary-section",
            )

        yield Static(
            "IMPORTANT: open a NEW terminal and confirm you can log in before "
            "closing this session. If you cannot get back in, use the rollback "
            "script above from the console.",
            classes="summary-warning",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-next":
            event.stop()
            self.app.exit()
            return
        super().on_button_pressed(event)
