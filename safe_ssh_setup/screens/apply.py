from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, ProgressBar, RichLog, Static

from safe_ssh_setup.executor import ActionExecutor
from safe_ssh_setup.models import PlannedAction
from safe_ssh_setup.screens.base import WizardScreen


class ApplyScreen(WizardScreen):
    step_name = "apply"
    can_skip = False

    def compose_step(self) -> ComposeResult:
        yield Static("Applying Changes", classes="section-header")
        yield Static(
            "Executing planned actions with automatic backup...",
            classes="section-description",
        )
        yield ProgressBar(total=100, id="apply-progress", classes="apply-progress")
        yield Label("Starting...", id="status-label")
        yield RichLog(id="apply-log", classes="apply-log", highlight=True, markup=True)

    def on_mount(self) -> None:
        # Disable Next button until apply is done
        try:
            next_btn = self.query_one("#btn-next")
            next_btn.disabled = True
        except Exception:
            pass

        self._run_apply()

    @staticmethod
    def _format_result(success: bool, action: PlannedAction, message: str) -> str:
        icon = "[green]OK[/green]" if success else "[red]FAIL[/red]"
        return f"[{icon}] {action.description}: {message}"

    def _run_apply(self) -> None:
        self.run_worker(self._apply_worker(), exclusive=True)

    async def _apply_worker(self) -> None:
        import asyncio

        executor = ActionExecutor(self.state)
        log = self.query_one("#apply-log", RichLog)
        progress = self.query_one("#apply-progress", ProgressBar)
        status = self.query_one("#status-label", Label)

        total = len(self.state.actions)
        if total == 0:
            status.update("No actions to apply.")
            return

        progress.update(total=total)
        results = []
        had_failure = False

        # Run in thread to avoid blocking the UI
        def execute():
            nonlocal results
            executor.prepare_backup_dir()

            for i, action in enumerate(self.state.actions):
                if i % 5 == 0:
                    from safe_ssh_setup.sudo import SudoHelper
                    SudoHelper.refresh_credentials()

                success, message = executor.execute_action(action)
                results.append((action, success, message))

                # Use call_from_thread for thread-safe UI updates
                self.app.call_from_thread(
                    self._update_progress, i + 1, total, action, success, message
                )

                if not success:
                    had_failure = True
                    if (
                        action.target in ("ssh", "sshd")
                        and "Validate" in action.description
                    ):
                        executor._restore_sshd_config()
                        self.app.call_from_thread(
                            log.write,
                            "[yellow]sshd_config validation failed — original restored[/yellow]"
                        )
                        break

            executor._generate_rollback_script()
            executor._save_manifest()
            self.state.applied = True

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, execute)

        # Re-enable Next button
        try:
            next_btn = self.query_one("#btn-next")
            next_btn.disabled = False
        except Exception:
            pass

        if had_failure:
            status.update("Completed with errors. Check log for details.")
        else:
            status.update(f"All {total} actions applied successfully!")

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
        log.write(self._format_result(success, action, message))
