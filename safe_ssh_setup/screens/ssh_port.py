from __future__ import annotations

import random

from textual.app import ComposeResult
from textual.widgets import Input, Label, RadioButton, RadioSet, Static

from safe_ssh_setup.screens.base import WizardScreen


class SSHPortScreen(WizardScreen):
    step_name = "ssh_port"

    def compose_step(self) -> ComposeResult:
        yield Static("SSH Port Selection", classes="section-header")
        yield Static(
            "Moving SSH off port 22 reduces noise from automated scanners. "
            "It's not security by itself, but it cuts down on log spam significantly.",
            classes="section-description",
        )

        self._random_port = random.randint(10000, 60000)

        yield RadioSet(
            RadioButton(
                f"Random high port ({self._random_port})",
                id="radio-random",
                value=True,
            ),
            RadioButton("Keep default port 22", id="radio-default"),
            RadioButton("Custom port", id="radio-custom"),
            id="port-choice",
        )

        yield Label("Custom port:")
        yield Input(
            placeholder="e.g. 2222",
            id="custom-port",
            type="integer",
            disabled=True,
        )

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        custom_input = self.query_one("#custom-port", Input)
        custom_input.disabled = event.pressed.id != "radio-custom"

    def validate_step(self) -> str | None:
        port = self._get_selected_port()
        if port is None:
            return "Please enter a valid port number."
        if not 1 <= port <= 65535:
            return "Port must be between 1 and 65535."
        return None

    def _get_selected_port(self) -> int | None:
        radio_set = self.query_one("#port-choice", RadioSet)
        pressed = radio_set.pressed_button
        if pressed is None:
            return self._random_port

        if pressed.id == "radio-random":
            return self._random_port
        elif pressed.id == "radio-default":
            return 22
        else:
            try:
                return int(self.query_one("#custom-port", Input).value)
            except (ValueError, TypeError):
                return None

    def save_state(self) -> None:
        port = self._get_selected_port()
        if port is not None:
            self.state.ssh_config.port = port
