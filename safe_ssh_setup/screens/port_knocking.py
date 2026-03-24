from __future__ import annotations

from datetime import datetime

from jinja2 import Environment, PackageLoader
from textual.app import ComposeResult
from textual.widgets import Input, Label, Static, Switch

from safe_ssh_setup.distro import PackageManager, detect_distro
from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.sudo import SudoHelper


class PortKnockingScreen(WizardScreen):
    step_name = "port_knocking"

    def compose_step(self) -> ComposeResult:
        yield Static("Port Knocking", classes="section-header")
        yield Static(
            "Port knocking hides your SSH port from scanners. "
            "The port only opens after a secret sequence of connection "
            "attempts to specific ports. This adds an extra layer of "
            "obscurity on top of your other security measures.",
            classes="section-description",
        )

        yield Label("Enable port knocking")
        yield Switch(value=False, id="enable-knock")

        yield Static("Settings", classes="section-header")

        yield Label("Knock sequence (comma-separated ports):")
        yield Input(value="7000,8000,9000", id="knock-sequence")

        yield Label("Sequence timeout (seconds):")
        yield Input(value="5", id="knock-timeout", type="integer")

        yield Static(
            "\nTo connect after enabling port knocking:\n"
            "  knock -v server_ip 7000 8000 9000 && ssh -p PORT user@server_ip\n"
            "\n"
            "You'll need the 'knock' client on your connecting machine.",
            classes="section-description",
        )

    def save_state(self) -> None:
        enabled = self.query_one("#enable-knock", Switch).value
        self.state.port_knocking.enabled = enabled

        self.clear_step_actions()

        if not enabled:
            return

        seq_str = self.query_one("#knock-sequence", Input).value
        timeout = int(self.query_one("#knock-timeout", Input).value or "5")

        try:
            sequence = [int(p.strip()) for p in seq_str.split(",") if p.strip()]
        except ValueError:
            sequence = [7000, 8000, 9000]

        self.state.port_knocking.sequence = sequence
        self.state.port_knocking.seq_timeout = timeout

        distro = detect_distro()
        pm = PackageManager(distro)

        # Install knockd
        self.state.actions.append(PlannedAction(
            action_type=ActionType.INSTALL_PACKAGE,
            description="Install knockd",
            target="knockd",
            command=pm.install_command(["knockd"]),
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # Generate knockd.conf
        env = Environment(
            loader=PackageLoader("safe_ssh_setup", "templates"),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("knockd.j2")
        content = template.render(
            knock=self.state.port_knocking,
            ssh_port=self.state.ssh_config.port,
            timestamp=datetime.now().isoformat(),
        )

        original = SudoHelper.read_file("/etc/knockd.conf") or ""

        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Write knockd configuration",
            target="/etc/knockd.conf",
            content=content,
            original_content=original,
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.ENABLE_SERVICE,
            description="Enable and start knockd",
            target="knockd",
            command="systemctl enable --now knockd",
            requires_sudo=True,
            step_name=self.step_name,
        ))
