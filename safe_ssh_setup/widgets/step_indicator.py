from __future__ import annotations

from typing import Sequence

from rich.text import Text
from textual.app import RenderResult
from textual.widget import Widget


class StepIndicator(Widget):
    """Horizontal progress indicator showing all wizard steps.

    Labels come from the app's step table rather than a second hardcoded list,
    so adding or reordering a step cannot desynchronise the two.
    """

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
        labels: Sequence[str] = (),
    ) -> None:
        super().__init__()
        self.current_step = current_step
        self.total_steps = total_steps
        self.labels = list(labels)

    def _label(self, index: int) -> str:
        if index < len(self.labels):
            return self.labels[index]
        return f"S{index + 1}"

    def render(self) -> RenderResult:
        text = Text()
        for i in range(self.total_steps):
            label = self._label(i)

            if i < self.current_step:
                text.append(f" [*] {label} ", style="green")
            elif i == self.current_step:
                text.append(f" >>> {label} ", style="bold white")
            else:
                text.append(f" [ ] {label} ", style="grey70")

            if i < self.total_steps - 1:
                text.append("--", style="grey50")

        return text
