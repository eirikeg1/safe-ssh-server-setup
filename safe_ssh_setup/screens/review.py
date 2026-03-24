from __future__ import annotations

from itertools import groupby

from textual.app import ComposeResult
from textual.widgets import Collapsible, Label, Static

from safe_ssh_setup.models import ActionType
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.widgets.diff_view import DiffView


STEP_DISPLAY_NAMES = {
    "welcome": "Welcome",
    "ssh_port": "SSH Port",
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
            "Review all changes below before applying. "
            "Go back to modify any settings.",
            classes="section-description",
        )

        actions = self.state.actions
        if not actions:
            yield Label("No changes planned. Go back and configure some settings.")
            return

        yield Label(f"Total actions: {len(actions)}")
        yield Static("")

        # Group by step
        sorted_actions = sorted(actions, key=lambda a: a.step_name)
        for step_name, step_actions in groupby(sorted_actions, key=lambda a: a.step_name):
            display_name = STEP_DISPLAY_NAMES.get(step_name, step_name)
            action_list = list(step_actions)

            with Collapsible(title=f"{display_name} ({len(action_list)} actions)", collapsed=False):
                for action in action_list:
                    if action.action_type == ActionType.WRITE_FILE:
                        yield Static(
                            f"  Write: {action.target}",
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
                            f"  Install: {action.target}",
                            classes="action-summary",
                        )
                    elif action.action_type == ActionType.RUN_COMMAND:
                        yield Static(
                            f"  Run: {action.description}\n"
                            f"    $ {action.command}",
                            classes="action-summary",
                        )
                    elif action.action_type == ActionType.ENABLE_SERVICE:
                        yield Static(
                            f"  Enable service: {action.target}",
                            classes="action-summary",
                        )
                    elif action.action_type == ActionType.RESTART_SERVICE:
                        yield Static(
                            f"  Restart service: {action.target}",
                            classes="action-summary",
                        )
                    elif action.action_type == ActionType.SET_PERMISSIONS:
                        yield Static(
                            f"  Set permissions: {action.target} -> {action.permissions}",
                            classes="action-summary",
                        )
                    elif action.action_type == ActionType.CREATE_DIR:
                        yield Static(
                            f"  Create directory: {action.target}",
                            classes="action-summary",
                        )

    def validate_step(self) -> str | None:
        if not self.state.actions:
            return "No changes to apply. Go back and configure some settings."
        return None
