from __future__ import annotations

from datetime import datetime

from textual.app import ComposeResult
from textual.widgets import Input, Label, Static, Switch

from safe_ssh_setup.distro import FirewallAdapter, PackageManager
from safe_ssh_setup.models import ActionType, DistroFamily, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.screens.ssh_hardening import build_environment
from safe_ssh_setup.sudo import SudoHelper
from safe_ssh_setup.system import default_interface
from safe_ssh_setup.validation import (
    ValidationError,
    parse_knock_sequence,
    validate_positive,
)

KNOCKD_OVERRIDE_DIR = "/etc/systemd/system/knockd.service.d"
KNOCKD_OVERRIDE = f"{KNOCKD_OVERRIDE_DIR}/safe-ssh-setup.conf"


class PortKnockingScreen(WizardScreen):
    step_name = "port_knocking"

    def compose_step(self) -> ComposeResult:
        cfg = self.state.port_knocking

        yield Static("Port Knocking", classes="section-header")
        yield Static(
            "Port knocking hides your SSH port from scanners. The port stays "
            "closed until a secret sequence of connection attempts arrives, "
            "then knockd opens it for that client's IP only.",
            classes="section-description",
        )

        yield Static(
            "If knockd fails to start, or you lose the knock client, the SSH "
            "port stays closed and you cannot connect. Leave this off unless "
            "you have console access as a fallback.",
            classes="summary-warning",
        )

        yield Label("Enable port knocking")
        yield Switch(value=cfg.enabled, id="enable-knock")

        yield Label("I understand the lockout risk")
        yield Switch(value=cfg.risk_acknowledged, id="ack-knock")

        yield Static("Settings", classes="section-header")

        yield Label("Knock sequence (comma-separated ports, at least 3):")
        yield Input(
            value=",".join(str(p) for p in cfg.sequence), id="knock-sequence"
        )

        yield Label("Sequence timeout (seconds):")
        yield Input(value=str(cfg.seq_timeout), id="knock-timeout", type="integer")

        iface = default_interface()
        yield Static(
            "\nTo connect after enabling port knocking:\n"
            f"  knock -v server_ip {' '.join(str(p) for p in cfg.sequence)} "
            f"&& ssh -p {self.state.ssh_config.port} user@server_ip\n"
            "\n"
            "You'll need the 'knock' client on your connecting machine."
            + (f"\nknockd will listen on interface: {iface}" if iface else ""),
            classes="section-description",
        )

    def validate_step(self) -> str | None:
        if not self.query_one("#enable-knock", Switch).value:
            return None
        if not self.query_one("#ack-knock", Switch).value:
            return (
                "Port knocking closes your SSH port by default. Acknowledge "
                "the lockout risk to continue, or turn port knocking off."
            )
        try:
            parse_knock_sequence(self.query_one("#knock-sequence", Input).value)
            validate_positive(
                self.query_one("#knock-timeout", Input).value, "Timeout"
            )
        except ValidationError as e:
            return str(e)
        return None

    def skip_step(self) -> None:
        super().skip_step()
        self.state.port_knocking.enabled = False
        self.state.port_knocking.risk_acknowledged = False

    def save_state(self) -> None:
        enabled = self.query_one("#enable-knock", Switch).value
        self.state.port_knocking.enabled = enabled
        self.state.port_knocking.risk_acknowledged = self.query_one(
            "#ack-knock", Switch
        ).value

        self.clear_step_actions()
        if not enabled:
            return

        cfg = self.state.port_knocking
        cfg.sequence = parse_knock_sequence(
            self.query_one("#knock-sequence", Input).value
        )
        cfg.seq_timeout = validate_positive(
            self.query_one("#knock-timeout", Input).value, "Timeout"
        )

        distro = self.state.distro_info
        if not distro:
            return

        pm = PackageManager(distro)
        adapter = FirewallAdapter(distro)
        port = self.state.ssh_config.port
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

        # Resolved per distro: Fedora/RHEL ship knockd inside "knock-server".
        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description=f"Install knockd ({pm.resolve('knockd')})",
            target="knockd",
            command=pm.install_command(["knockd"]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        content = env.get_template("knockd.j2").render(
            knock=cfg,
            ssh_port=port,
            firewall_name=distro.firewall,
            open_command=adapter.knock_open_command(port),
            close_command=adapter.knock_close_command(port),
            timestamp=timestamp,
        )

        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Write knockd configuration",
            target="/etc/knockd.conf",
            content=content,
            original_content=SudoHelper.read_file("/etc/knockd.conf") or "",
            permissions="0600",
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Debian's init wrapper refuses to start knockd until this is set.
        if distro.family == DistroFamily.DEBIAN:
            self.state.actions.append(PlannedAction(
                action_type=ActionType.WRITE_FILE,
                description="Enable knockd in /etc/default/knockd",
                target="/etc/default/knockd",
                content=(
                    "# Generated by safe-ssh-setup\n"
                    "START_KNOCKD=1\n"
                    'KNOCKD_OPTS=""\n'
                ),
                original_content=SudoHelper.read_file("/etc/default/knockd") or "",
                requires_sudo=True,
                step_name=self.step_name,
            ))

        iface = default_interface()
        if iface:
            override = env.get_template("knockd_service_override.j2").render(
                interface=iface,
                timestamp=timestamp,
            )
            self.state.actions.append(PlannedAction(
                action_type=ActionType.WRITE_FILE,
                description=f"Pin knockd to interface {iface}",
                target=KNOCKD_OVERRIDE,
                content=override,
                original_content=SudoHelper.read_file(KNOCKD_OVERRIDE) or "",
                requires_sudo=True,
                step_name=self.step_name,
            ))
            self.state.actions.append(PlannedAction(
                action_type=ActionType.RUN_COMMAND,
                description="Reload systemd units",
                target="systemd",
                command=["systemctl", "daemon-reload"],
                requires_sudo=True,
                step_name=self.step_name,
            ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.ENABLE_SERVICE,
            description="Enable and start knockd",
            target="knockd",
            command=["systemctl", "enable", "--now", "knockd"],
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Safety net: with knocking on, the firewall left the SSH port closed.
        # If knockd is not actually running, re-open the port rather than
        # leaving a box nobody can reach.
        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description=(
                "Verify knockd is running (re-opens the SSH port if it is not)"
            ),
            target="knockd",
            command=["systemctl", "is-active", "knockd"],
            fallback_command=adapter.allow_port_argv(port),
            ignore_failure=True,
            requires_sudo=True,
            step_name=self.step_name,
        ))
