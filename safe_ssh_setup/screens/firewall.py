from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, Static, Switch

from safe_ssh_setup.distro import FirewallAdapter, PackageManager
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.system import default_interface


class FirewallScreen(WizardScreen):
    step_name = "firewall"

    def compose_step(self) -> ComposeResult:
        distro = self.state.distro_info
        cfg = self.state.firewall

        yield Static("Firewall Configuration", classes="section-header")

        if not distro:
            yield Static("Distribution not detected; go back to the Welcome step.")
            return

        adapter = FirewallAdapter(distro)
        fw_name = distro.firewall.upper()

        yield Static(
            f"Configure {fw_name} to allow SSH traffic on your chosen port "
            "and deny everything else.",
            classes="section-description",
        )

        yield Label("Enable firewall")
        yield Switch(value=cfg.enabled, id="enable-fw")

        yield Label("Default deny incoming traffic")
        yield Switch(value=cfg.default_deny, id="default-deny")

        if adapter.supports_rate_limiting:
            yield Label("Enable rate limiting (recommended)")
            yield Switch(value=cfg.rate_limiting, id="rate-limit")
        else:
            yield Static(
                "Rate limiting is not offered on firewalld: its rich-rule "
                "limit applies to the rule as a whole rather than per source "
                "address, so a single attacker could exhaust the limit and "
                "lock you out. Fail2Ban provides brute-force protection here.",
                classes="section-description",
            )

        iface = default_interface()
        details = [
            f"Firewall tool: {fw_name}",
            f"SSH port: {self.state.ssh_config.port}",
        ]
        if distro.firewall == "firewalld" and iface:
            details.append(f"Interface bound to the managed zone: {iface}")
        if self.state.port_knocking.enabled:
            details.append(
                "Port knocking is enabled, so the SSH port will NOT be opened "
                "permanently — knockd opens it per client."
            )

        yield Static("\n" + "\n".join(details), classes="section-description")

    def skip_step(self) -> None:
        super().skip_step()
        self.state.firewall.enabled = False

    def save_state(self) -> None:
        distro = self.state.distro_info
        if not distro:
            return

        adapter = FirewallAdapter(distro)
        enabled = self.query_one("#enable-fw", Switch).value
        default_deny = self.query_one("#default-deny", Switch).value
        rate_limit = (
            self.query_one("#rate-limit", Switch).value
            if adapter.supports_rate_limiting
            else False
        )

        self.state.firewall.enabled = enabled
        self.state.firewall.default_deny = default_deny
        self.state.firewall.rate_limiting = rate_limit

        self.clear_step_actions()
        if not enabled:
            return

        pm = PackageManager(distro)
        port = self.state.ssh_config.port

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
            description=f"Install {distro.firewall}",
            target=distro.firewall,
            command=pm.install_command(adapter.install_packages()),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # The adapter owns ordering: firewalld must be running before any
        # firewall-cmd call, and the SSH port is opened before default-deny.
        for step in adapter.plan(
            port=port,
            rate_limiting=rate_limit,
            default_deny=default_deny,
            # With knocking on, knockd opens the port per client instead.
            open_ssh_port=not self.state.port_knocking.enabled,
        ):
            self.state.actions.append(PlannedAction(
                action_type=ActionType.RUN_COMMAND,
                description=step.description,
                target="firewall",
                command=step.argv,
                ignore_failure=step.ignore_failure,
                ok_returncodes=step.ok_returncodes,
                requires_sudo=True,
                step_name=self.step_name,
            ))
