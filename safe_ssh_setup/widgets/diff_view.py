from __future__ import annotations

import difflib

from rich.text import Text
from textual.widgets import Static


class DiffView(Static):
    """Displays a colored unified diff between original and modified content."""

    DEFAULT_CSS = """
    DiffView {
        padding: 1 2;
        background: $surface-lighten-1;
        border: round $accent;
    }
    """

    def __init__(
        self,
        original: str,
        modified: str,
        filename: str,
    ) -> None:
        self._original = original
        self._modified = modified
        self._filename = filename
        super().__init__()

    def on_mount(self) -> None:
        diff = difflib.unified_diff(
            self._original.splitlines(keepends=True),
            self._modified.splitlines(keepends=True),
            fromfile=f"a/{self._filename}",
            tofile=f"b/{self._filename}",
            lineterm="",
        )

        text = Text()
        for line in diff:
            line = line.rstrip("\n")
            if line.startswith("+++") or line.startswith("---"):
                text.append(line + "\n", style="bold cyan")
            elif line.startswith("@@"):
                text.append(line + "\n", style="magenta")
            elif line.startswith("+"):
                text.append(line + "\n", style="green")
            elif line.startswith("-"):
                text.append(line + "\n", style="red")
            else:
                text.append(line + "\n")

        if not text.plain.strip():
            text.append("(no changes)", style="italic grey70")

        self.update(text)
