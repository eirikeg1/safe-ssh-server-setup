from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header

from safe_ssh_setup.models import WizardState
from safe_ssh_setup.widgets.nav_bar import NavBar
from safe_ssh_setup.widgets.step_indicator import StepIndicator


class WizardScreen(Screen):
    """Base class for all wizard step screens."""

    step_name: str = ""
    can_skip: bool = True
    next_label: str = "Next"

    def __init__(
        self,
        state: WizardState,
        step_index: int,
        total_steps: int,
    ) -> None:
        super().__init__()
        self.state = state
        self.step_index = step_index
        self.total_steps = total_steps

    def compose(self) -> ComposeResult:
        yield Header()
        yield StepIndicator(self.step_index, self.total_steps)
        with VerticalScroll(id="step-content"):
            yield from self.compose_step()
        yield NavBar(
            show_back=self.step_index > 0,
            show_skip=self.can_skip,
            show_next=True,
            next_label=self.next_label,
        )
        yield Footer()

    def compose_step(self) -> ComposeResult:
        """Override in subclasses to yield step-specific widgets."""
        raise NotImplementedError

    def validate_step(self) -> str | None:
        """Return an error message if step is invalid, or None if OK."""
        return None

    def save_state(self) -> None:
        """Save widget values into self.state. Called before advancing."""
        pass

    def clear_step_actions(self) -> None:
        """Remove any previously generated actions from this step."""
        self.state.actions = [
            a for a in self.state.actions if a.step_name != self.step_name
        ]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-next":
            error = self.validate_step()
            if error:
                self.notify(error, severity="error")
                return
            self.save_state()
            self.app.action_next_step()
        elif event.button.id == "btn-back":
            self.app.action_prev_step()
        elif event.button.id == "btn-skip":
            self.app.action_next_step()
