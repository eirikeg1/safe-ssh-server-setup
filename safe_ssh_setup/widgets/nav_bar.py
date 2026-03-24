from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button


class NavBar(Widget):
    """Bottom navigation bar with Back, Skip, and Next buttons."""

    DEFAULT_CSS = """
    NavBar {
        height: auto;
        padding: 1 2;
        dock: bottom;
        background: $surface-lighten-1;
        layout: horizontal;
        align: center middle;
    }

    NavBar Button {
        margin: 0 1;
        min-width: 14;
    }

    NavBar #btn-next {
        background: $accent;
    }

    NavBar #btn-skip {
        background: $warning;
    }
    """

    def __init__(
        self,
        show_back: bool = True,
        show_skip: bool = True,
        show_next: bool = True,
        next_label: str = "Next",
    ) -> None:
        super().__init__()
        self._show_back = show_back
        self._show_skip = show_skip
        self._show_next = show_next
        self._next_label = next_label

    def compose(self) -> ComposeResult:
        with Horizontal():
            if self._show_back:
                yield Button("Back", id="btn-back", variant="default")
            if self._show_skip:
                yield Button("Skip", id="btn-skip", variant="warning")
            if self._show_next:
                yield Button(self._next_label, id="btn-next", variant="success")
