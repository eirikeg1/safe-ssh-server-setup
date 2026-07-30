from __future__ import annotations

from itertools import groupby

from textual.app import ComposeResult
from textual.widgets import Collapsible, Label, Static

from safe_ssh_setup.models import ActionType, ordered_actions
from safe_ssh_setup.safety import check_lockout_risks
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.sudo import format_command
from safe_ssh_setup.widgets.diff_view import DiffView

STEP_DISPLAY_NAMES = {
    "welcome": "Prerequisites",
    "ssh_key": "SSH Key Setup",
    "ssh_hardening": "SSH Hardening",
    "fail2ban": "Fail2Ban",
    "firewall": "Firewall",
    "auto_updates": "Auto Updates",
    "port_knocking": "Port Knocking",
    "intrusion_detection": "Intrusion Detection",
}


class ReviewScreen(WizardScreen):
    step_name = "review"
    can_skip = False
    next_label = "Apply"

    def compose_step(self) -> ComposeResult:
        yield Static("Review Planned Changes", classes="section-header")
        yield Static(
            "Everything below runs in the order shown. Nothing has been "
            "changed yet — go back to modify any settings.",
            classes="section-description",
        )

        problems = check_lockout_risks(self.state)
        if problems:
            yield Static(
                "Cannot apply yet — this configuration would lock you out:\n\n"
                + "\n\n".join(f"  - {p}" for p in problems),
                classes="summary-warning",
            )

        # Canonical execution order, not the order steps were visited and not
        # alphabetical — what is displayed is what will run.
        actions = ordered_actions(self.state.actions)
        if not actions:
            yield Label("No changes planned. Go back and configure some settings.")
            return

        yield Label(f"Total actions: {len(actions)}")
        yield Static("")

        position = 0
        for step_name, group in groupby(actions, key=lambda a: a.step_name):
            display_name = STEP_DISPLAY_NAMES.get(step_name, step_name)
            step_actions = list(group)

            with Collapsible(
                title=f"{display_name} ({len(step_actions)} actions)",
                collapsed=False,
            ):
                for action in step_actions:
                    position += 1
                    yield from self._render_action(position, action)

    def _render_action(self, position: int, action) -> ComposeResult:
        flags = []
        if action.critical:
            flags.append("aborts the run if it fails")
        if action.ignore_failure:
            flags.append("best effort")
        suffix = f"  [{'; '.join(flags)}]" if flags else ""

        if action.action_type == ActionType.WRITE_FILE:
            yield Static(
                f"  {position}. Write: {action.target}{suffix}",
                classes="action-summary",
            )
            if action.original_content is not None and action.content is not None:
                yield DiffView(
                    original=action.original_content,
                    modified=action.content,
                    filename=action.target,
                )
        elif action.action_type == ActionType.INSTALL_PACKAGE:
            yield Static(
                f"  {position}. Install: {action.target}{suffix}\n"
                f"    $ {format_command(action.command)}",
                classes="action-summary",
            )
        elif action.action_type == ActionType.APPEND_AUTHORIZED_KEY:
            key = action.public_key or f"public key from {action.key_path}.pub"
            yield Static(
                f"  {position}. Add key to {action.target}{suffix}\n"
                f"    {key}",
                classes="action-summary",
            )
        elif action.action_type == ActionType.GENERATE_SSH_KEY:
            yield Static(
                f"  {position}. Generate Ed25519 key pair: {action.target}{suffix}",
                classes="action-summary",
            )
        elif action.action_type == ActionType.VERIFY_SSH:
            yield Static(
                f"  {position}. Verify {action.service} is listening on port "
                f"{action.port}{suffix}",
                classes="action-summary",
            )
        else:
            command = format_command(action.command)
            body = f"  {position}. {action.description}{suffix}"
            if command:
                body += f"\n    $ {command}"
            yield Static(body, classes="action-summary")

    def validate_step(self) -> str | None:
        if not self.state.actions:
            return "No changes to apply. Go back and configure some settings."
        problems = check_lockout_risks(self.state)
        if problems:
            return problems[0]
        return None
