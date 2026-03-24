from __future__ import annotations

from rich.text import Text
from textual.widget import Widget
from textual.app import RenderResult


STEP_LABELS = [
    "Welcome",
    "Port",
    "Key",
    "Harden",
    "Fail2Ban",
    "Firewall",
    "Updates",
    "Knock",
    "IDS",
    "Review",
    "Apply",
    "Done",
]


class StepIndicator(Widget):
    """Horizontal progress indicator showing all wizard steps."""

    DEFAULT_CSS = """
    StepIndicator {
        height: 3;
        padding: 0 1;
        background: $surface-lighten-1;
    }
    """

    def __init__(
        self,
        current_step: int,
        total_steps: int,
    ) -> None:
        super().__init__()
        self.current_step = current_step
        self.total_steps = total_steps

    def render(self) -> RenderResult:
        text = Text()
        for i in range(self.total_steps):
            label = STEP_LABELS[i] if i < len(STEP_LABELS) else f"S{i + 1}"

            if i < self.current_step:
                text.append(f" [*] {label} ", style="green")
            elif i == self.current_step:
                text.append(f" >>> {label} ", style="bold white")
            else:
                text.append(f" [ ] {label} ", style="grey70")

            if i < self.total_steps - 1:
                text.append("--", style="grey50")

        return text

    def update_step(self, step: int) -> None:
        self.current_step = step
        self.refresh()
