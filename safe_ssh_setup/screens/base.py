from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header

from safe_ssh_setup.models import WizardState
from safe_ssh_setup.widgets.nav_bar import NavBar
from safe_ssh_setup.widgets.step_indicator import StepIndicator


class WizardScreen(Screen):
    """Base class for all wizard step screens.

    Screens are rebuilt whenever they are shown, so every subclass must derive
    its widget values from ``self.state`` rather than hardcoding defaults.
    Otherwise navigating Back and then Next silently reverts the user's input.
    """

    step_name: str = ""
    can_skip: bool = True
    can_go_back: bool = True
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
        yield StepIndicator(
            self.step_index,
            self.total_steps,
            labels=getattr(self.app, "step_labels", ()),
        )
        with VerticalScroll(id="step-content"):
            yield from self.compose_step()
        yield NavBar(
            show_back=self.step_index > 0 and self.can_go_back,
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

    def skip_step(self) -> None:
        """Undo this step.

        Skipping must remove anything the step planned on an earlier visit,
        otherwise configuring a step and then skipping it still applies it.
        """
        self.clear_step_actions()

    def clear_step_actions(self) -> None:
        """Remove any previously generated actions from this step."""
        self.state.actions = [
            a for a in self.state.actions if a.step_name != self.step_name
        ]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-next":
            event.stop()
            error = self.validate_step()
            if error:
                self.notify(error, severity="error", timeout=10)
                return
            self.save_state()
            self.app.action_next_step()
        elif event.button.id == "btn-back":
            event.stop()
            self.app.action_prev_step()
        elif event.button.id == "btn-skip":
            event.stop()
            self.skip_step()
            self.app.action_next_step()
