from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Input, Label, RadioButton, RadioSet, Static

from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.system import ephemeral_port_floor, listening_ports
from safe_ssh_setup.validation import (
    ValidationError,
    parse_port,
    pick_random_port,
    validate_port,
)

PORT_DEPENDENT_STEPS = ["fail2ban", "firewall", "port_knocking"]


class SSHPortScreen(WizardScreen):
    step_name = "ssh_port"

    def compose_step(self) -> ComposeResult:
        yield Static("SSH Port Selection", classes="section-header")
        yield Static(
            "Moving SSH off port 22 reduces noise from automated scanners. "
            "It's not security by itself, but it cuts down on log spam "
            "significantly.",
            classes="section-description",
        )

        # Generated once and remembered, so revisiting this screen does not
        # roll a different port than the one already reviewed.
        if not self.state.random_port:
            self.state.random_port = pick_random_port(
                ephemeral_port_floor(),
                in_use=listening_ports(),
            )
        random_port = self.state.random_port
        choice = self.state.port_choice

        yield Static(
            f"Ports at or above {ephemeral_port_floor()} are handed out to "
            "outbound connections, so the suggested port stays below that "
            "range to avoid intermittent bind failures at boot.",
            classes="section-description",
        )

        yield RadioSet(
            RadioButton(
                f"Random high port ({random_port})",
                id="radio-random",
                value=choice == "random",
            ),
            RadioButton(
                "Keep default port 22",
                id="radio-default",
                value=choice == "default",
            ),
            RadioButton(
                "Custom port",
                id="radio-custom",
                value=choice == "custom",
            ),
            id="port-choice",
        )

        yield Label("Custom port:")
        yield Input(
            value=(
                str(self.state.ssh_config.port) if choice == "custom" else ""
            ),
            placeholder="e.g. 2222",
            id="custom-port",
            type="integer",
            disabled=choice != "custom",
        )

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        custom_input = self.query_one("#custom-port", Input)
        custom_input.disabled = event.pressed.id != "radio-custom"

    def _choice(self) -> str:
        radio_set = self.query_one("#port-choice", RadioSet)
        pressed = radio_set.pressed_button
        if pressed is None:
            return "random"
        return {
            "radio-random": "random",
            "radio-default": "default",
            "radio-custom": "custom",
        }.get(pressed.id or "", "random")

    def _selected_port(self) -> int:
        choice = self._choice()
        if choice == "random":
            return self.state.random_port
        if choice == "default":
            return 22
        return parse_port(self.query_one("#custom-port", Input).value)

    def validate_step(self) -> str | None:
        try:
            port = self._selected_port()
            validate_port(port)
        except ValidationError as e:
            return str(e)

        # The port sshd already uses is not a conflict — otherwise you could
        # neither keep port 22 nor re-run the wizard with your current port.
        if port != self.state.existing_ssh_port and port in listening_ports():
            return (
                f"Port {port} is already in use by another service. "
                "Choose a different port."
            )
        return None

    def save_state(self) -> None:
        try:
            port = self._selected_port()
        except ValidationError:
            return

        self.state.port_choice = self._choice()
        old_port = self.state.ssh_config.port
        self.state.ssh_config.port = port

        # Downstream steps bake the port into their commands and configs.
        if port != old_port:
            self.state.actions = [
                a for a in self.state.actions
                if a.step_name not in PORT_DEPENDENT_STEPS
            ]
