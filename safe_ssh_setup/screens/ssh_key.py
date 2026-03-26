from __future__ import annotations

import os
import re
from pathlib import Path

from textual.app import ComposeResult
from textual.widgets import Input, Label, RadioButton, RadioSet, Static, Switch, TextArea

from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen

PUBLIC_KEY_PATTERN = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|ssh-dss)\s+\S+"
)


class SSHKeyScreen(WizardScreen):
    step_name = "ssh_key"

    def compose_step(self) -> ComposeResult:
        yield Static("SSH Key Setup", classes="section-header")
        yield Static(
            "To connect securely, your client machine's public key must be "
            "added to this server's authorized_keys file.",
            classes="section-description",
        )

        yield RadioSet(
            RadioButton(
                "Paste a public key from my client (recommended)",
                id="radio-paste",
                value=True,
            ),
            RadioButton(
                "Generate a new key pair on this server",
                id="radio-generate",
            ),
            id="key-mode",
        )

        # Paste mode widgets
        yield Static(
            "\nOn your client machine, run:\n"
            "  cat ~/.ssh/id_ed25519.pub\n\n"
            "Then paste the output below:",
            classes="section-description",
            id="paste-instructions",
        )
        yield TextArea(id="pubkey-input")

        # Generate mode widgets
        home = Path.home()
        default_path = str(home / ".ssh" / "id_ed25519")

        yield Label("Key path:", id="keypath-label")
        yield Input(value=default_path, id="key-path", disabled=True)

    def on_mount(self) -> None:
        self._update_mode_visibility()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self._update_mode_visibility()

    def _update_mode_visibility(self) -> None:
        radio_set = self.query_one("#key-mode", RadioSet)
        pressed = radio_set.pressed_button
        is_paste = pressed is None or pressed.id == "radio-paste"

        self.query_one("#paste-instructions").display = is_paste
        self.query_one("#pubkey-input").display = is_paste
        self.query_one("#keypath-label").display = not is_paste
        self.query_one("#key-path").disabled = is_paste
        self.query_one("#key-path", Input).display = not is_paste

    def _is_paste_mode(self) -> bool:
        radio_set = self.query_one("#key-mode", RadioSet)
        pressed = radio_set.pressed_button
        return pressed is None or pressed.id == "radio-paste"

    def validate_step(self) -> str | None:
        if self._is_paste_mode():
            pubkey = self.query_one("#pubkey-input", TextArea).text.strip()
            if not pubkey:
                return "Please paste your public key."
            if not PUBLIC_KEY_PATTERN.match(pubkey):
                return (
                    "That doesn't look like a valid public key. "
                    "It should start with ssh-ed25519, ssh-rsa, or ecdsa-sha2-..."
                )
        return None

    def save_state(self) -> None:
        self.clear_step_actions()

        ssh_dir = str(Path.home() / ".ssh")
        auth_keys = str(Path(ssh_dir) / "authorized_keys")

        # Ensure .ssh directory exists with correct permissions
        self.state.actions.append(PlannedAction(
            action_type=ActionType.CREATE_DIR,
            description=f"Create SSH directory {ssh_dir}",
            target=ssh_dir,
            command=f"mkdir -p {ssh_dir}",
            requires_sudo=False,
            step_name=self.step_name,
        ))
        self.state.actions.append(PlannedAction(
            action_type=ActionType.SET_PERMISSIONS,
            description="Set SSH directory permissions to 700",
            target=ssh_dir,
            permissions="700",
            command=f"chmod 700 {ssh_dir}",
            requires_sudo=False,
            step_name=self.step_name,
        ))

        if self._is_paste_mode():
            # Paste mode: write the client's public key to authorized_keys
            pubkey = self.query_one("#pubkey-input", TextArea).text.strip()
            self.state.ssh_key.generate_key = False
            self.state.ssh_key.setup_authorized_keys = True

            self.state.actions.append(PlannedAction(
                action_type=ActionType.RUN_COMMAND,
                description="Add client public key to authorized_keys",
                target=auth_keys,
                command=(
                    f'touch "{auth_keys}" && '
                    f'grep -qF "{pubkey}" "{auth_keys}" 2>/dev/null || '
                    f'echo "{pubkey}" >> "{auth_keys}"'
                ),
                requires_sudo=False,
                step_name=self.step_name,
            ))
        else:
            # Generate mode: create a key pair on this server
            key_path = self.query_one("#key-path", Input).value
            key_path_str = key_path or str(Path.home() / ".ssh" / "id_ed25519")
            user = os.environ.get("USER", "root")

            self.state.ssh_key.generate_key = True
            self.state.ssh_key.key_path = Path(key_path_str)

            self.state.actions.append(PlannedAction(
                action_type=ActionType.RUN_COMMAND,
                description=f"Generate Ed25519 SSH key at {key_path_str}",
                target=key_path_str,
                command=(
                    f'[ -f "{key_path_str}" ] && echo "Key already exists, skipping" || '
                    f'ssh-keygen -t ed25519 -f "{key_path_str}" -N "" -C "{user}@safe-ssh-setup"'
                ),
                requires_sudo=False,
                step_name=self.step_name,
            ))

            self.state.actions.append(PlannedAction(
                action_type=ActionType.SET_PERMISSIONS,
                description="Set private key permissions to 600",
                target=key_path_str,
                permissions="600",
                command=f'[ -f "{key_path_str}" ] && chmod 600 "{key_path_str}" || true',
                requires_sudo=False,
                step_name=self.step_name,
            ))

            self.state.actions.append(PlannedAction(
                action_type=ActionType.RUN_COMMAND,
                description="Add public key to authorized_keys",
                target=auth_keys,
                command=(
                    f'touch "{auth_keys}" && '
                    f'grep -qF "$(cat "{key_path_str}.pub")" "{auth_keys}" 2>/dev/null || '
                    f'cat "{key_path_str}.pub" >> "{auth_keys}"'
                ),
                requires_sudo=False,
                step_name=self.step_name,
            ))

        # Set authorized_keys permissions
        self.state.actions.append(PlannedAction(
            action_type=ActionType.SET_PERMISSIONS,
            description="Set authorized_keys permissions to 600",
            target=auth_keys,
            permissions="600",
            command=f'chmod 600 "{auth_keys}"',
            requires_sudo=False,
            step_name=self.step_name,
        ))
