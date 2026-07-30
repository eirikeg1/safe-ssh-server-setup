from __future__ import annotations

import asyncio

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Label, ProgressBar, RichLog, Static

from safe_ssh_setup.executor import ActionExecutor
from safe_ssh_setup.models import PlannedAction
from safe_ssh_setup.screens.base import WizardScreen


class ApplyScreen(WizardScreen):
    step_name = "apply"
    can_skip = False
    # Going back and forward again would re-run the whole plan against
    # already-modified files, destroying the backup baseline.
    can_go_back = False

    # Quitting mid-apply would leave the system half-configured.
    BINDINGS = [
        Binding("q", "noop", "Quit (disabled while applying)", show=False),
    ]

    def compose_step(self) -> ComposeResult:
        yield Static("Applying Changes", classes="section-header")
        yield Static(
            "Executing planned actions. Every file is backed up first, and a "
            "rollback script is written before anything changes.",
            classes="section-description",
        )
        yield ProgressBar(total=100, id="apply-progress", classes="apply-progress")
        yield Label("Starting...", id="status-label")
        yield RichLog(id="apply-log", classes="apply-log", highlight=True, markup=True)

    def action_noop(self) -> None:
        if self.state.apply_in_progress:
            self.notify(
                "Cannot quit while changes are being applied.",
                severity="warning",
            )
        else:
            self.app.exit()

    def on_mount(self) -> None:
        self._set_next_enabled(False)
        # Applying twice would back up the files this run already rewrote.
        if self.state.applied:
            self._replay_previous_results()
            self._set_next_enabled(True)
            return
        self.run_worker(self._apply_worker(), exclusive=True)

    def _replay_previous_results(self) -> None:
        log = self.query_one("#apply-log", RichLog)
        status = self.query_one("#status-label", Label)
        progress = self.query_one("#apply-progress", ProgressBar)

        results = self.state.apply_results
        progress.update(total=max(len(results), 1), progress=len(results))
        for description, success, message in results:
            log.write(self._format_result(success, description, message))
        status.update("Already applied. Changes are not run twice.")

    def _set_next_enabled(self, enabled: bool) -> None:
        try:
            self.query_one("#btn-next").disabled = not enabled
        except Exception:  # noqa: BLE001 - button may not be mounted yet
            self.call_after_refresh(self._retry_set_next_enabled, enabled)

    def _retry_set_next_enabled(self, enabled: bool) -> None:
        try:
            self.query_one("#btn-next").disabled = not enabled
        except Exception:  # noqa: BLE001 - nothing more we can do
            pass

    @staticmethod
    def _format_result(success: bool, description: str, message: str) -> str:
        icon = "[green]OK[/green]" if success else "[red]FAIL[/red]"
        return f"[{icon}] {description}: {message}"

    async def _apply_worker(self) -> None:
        log = self.query_one("#apply-log", RichLog)
        status = self.query_one("#status-label", Label)
        progress = self.query_one("#apply-progress", ProgressBar)

        total = len(self.state.actions)
        if total == 0:
            status.update("No actions to apply.")
            self._set_next_enabled(True)
            return

        progress.update(total=total)
        executor = ActionExecutor(self.state)
        self.state.apply_in_progress = True

        def report(
            index: int,
            count: int,
            action: PlannedAction,
            success: bool,
            message: str,
        ) -> None:
            self.app.call_from_thread(
                self._update_progress, index, count, action, success, message
            )

        try:
            # to_thread rather than get_event_loop().run_in_executor: the
            # latter is deprecated inside a running coroutine.
            results = await asyncio.to_thread(executor.execute_all, report)
        except Exception as exc:  # noqa: BLE001 - must never strand the UI
            log.write(f"[red]Apply failed:[/red] {exc}")
            status.update("Apply failed before completing. See the log.")
            self.state.apply_succeeded = False
            return
        finally:
            self.state.apply_in_progress = False
            self._set_next_enabled(True)

        failures = [(a, m) for a, ok, m in results if not ok]

        if executor.aborted:
            status.update("Aborted — original SSH configuration restored.")
            log.write(
                "[yellow]Run aborted: "
                f"{executor.abort_reason}[/yellow]"
            )
            log.write(
                "[yellow]The firewall was not reconfigured, so your existing "
                "access is unchanged.[/yellow]"
            )
        elif failures:
            status.update(
                f"Completed with {len(failures)} failed action(s). "
                "Check the log before disconnecting."
            )
        else:
            status.update(f"All {len(results)} actions applied successfully.")

        if self.state.backup_dir:
            log.write(
                f"[cyan]Rollback:[/cyan] sudo bash {self.state.backup_dir}/rollback.sh"
            )

    def _update_progress(
        self,
        current: int,
        total: int,
        action: PlannedAction,
        success: bool,
        message: str,
    ) -> None:
        log = self.query_one("#apply-log", RichLog)
        progress = self.query_one("#apply-progress", ProgressBar)
        status = self.query_one("#status-label", Label)

        progress.update(progress=current)
        status.update(f"[{current}/{total}] {action.description}")
        log.write(self._format_result(success, action.description, message))
