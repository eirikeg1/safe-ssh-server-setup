from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, Static, Switch

from safe_ssh_setup.distro import FirewallAdapter, PackageManager, detect_distro
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen


class FirewallScreen(WizardScreen):
    step_name = "firewall"

    def compose_step(self) -> ComposeResult:
        yield Static("Firewall Configuration", classes="section-header")

        distro = detect_distro()
        fw_name = distro.firewall.upper()

        yield Static(
            f"Configure {fw_name} to only allow SSH traffic "
            f"on your chosen port and deny everything else.",
            classes="section-description",
        )

        yield Label("Enable firewall")
        yield Switch(value=True, id="enable-fw")

        yield Label("Enable rate limiting (recommended)")
        yield Switch(value=True, id="rate-limit")

        yield Static(
            f"\nFirewall tool: {fw_name}\n"
            f"SSH port: {self.state.ssh_config.port}",
            classes="section-description",
        )

    def save_state(self) -> None:
        enabled = self.query_one("#enable-fw", Switch).value
        rate_limit = self.query_one("#rate-limit", Switch).value
        self.state.firewall.enabled = enabled
        self.state.firewall.rate_limiting = rate_limit

        self.clear_step_actions()

        if not enabled:
            return

        distro = detect_distro()
        pm = PackageManager(distro)
        fw = FirewallAdapter(distro)
        port = self.state.ssh_config.port

        # Install firewall
        fw_packages = fw.install_packages()
        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description=f"Install {distro.firewall}",
            target=distro.firewall,
            command=pm.install_command(fw_packages),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Default deny
        for cmd in fw.default_deny_command():
            self.state.actions.append(PlannedAction(
                action_type=ActionType.RUN_COMMAND,
                description="Set default deny incoming",
                target="firewall",
                command=cmd,
                requires_sudo=True,
                step_name=self.step_name,
            ))

        # Remove default SSH rule if using non-standard port
        if port != 22:
            for cmd in fw.remove_ssh_default_commands():
                self.state.actions.append(PlannedAction(
                    action_type=ActionType.RUN_COMMAND,
                    description="Remove default SSH rule",
                    target="firewall",
                    command=cmd,
                    requires_sudo=True,
                    step_name=self.step_name,
                ))

        # Allow SSH port
        if rate_limit:
            for cmd in fw.rate_limit_commands(port):
                self.state.actions.append(PlannedAction(
                    action_type=ActionType.RUN_COMMAND,
                    description=f"Allow SSH port {port} with rate limiting",
                    target="firewall",
                    command=cmd,
                    requires_sudo=True,
                    step_name=self.step_name,
                ))
        else:
            for cmd in fw.allow_port_commands(port):
                self.state.actions.append(PlannedAction(
                    action_type=ActionType.RUN_COMMAND,
                    description=f"Allow SSH port {port}",
                    target="firewall",
                    command=cmd,
                    requires_sudo=True,
                    step_name=self.step_name,
                ))

        # Enable firewall
        for cmd in fw.enable_commands():
            self.state.actions.append(PlannedAction(
                action_type=ActionType.ENABLE_SERVICE,
                description=f"Enable {distro.firewall}",
                target=distro.firewall,
                command=cmd,
                requires_sudo=True,
                step_name=self.step_name,
            ))
