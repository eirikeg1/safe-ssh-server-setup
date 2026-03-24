from __future__ import annotations

import os
from pathlib import Path

from textual.app import ComposeResult
from textual.widgets import Input, Label, Static, Switch

from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen


class SSHKeyScreen(WizardScreen):
    step_name = "ssh_key"

    def compose_step(self) -> ComposeResult:
        yield Static("SSH Key Setup", classes="section-header")
        yield Static(
            "SSH keys are the recommended way to authenticate. "
            "An Ed25519 key will be generated — it's fast, secure, "
            "and produces short keys.",
            classes="section-description",
        )

        home = Path.home()
        default_path = str(home / ".ssh" / "id_ed25519")

        yield Label("Generate a new SSH key pair")
        yield Switch(value=True, id="generate-key")

        yield Label("Key path:")
        yield Input(value=default_path, id="key-path")

        yield Label("Set up authorized_keys for this key")
        yield Switch(value=True, id="setup-authorized-keys")

        yield Static("")
        yield Static(
            "After setup, copy the public key to your client machines:\n"
            f"  ssh-copy-id -i {default_path}.pub -p PORT user@this-server\n"
            "\n"
            "Or manually copy the public key content to your client's\n"
            "~/.ssh/authorized_keys file.",
            classes="section-description",
        )

    def save_state(self) -> None:
        generate = self.query_one("#generate-key", Switch).value
        key_path = self.query_one("#key-path", Input).value
        setup_auth = self.query_one("#setup-authorized-keys", Switch).value

        self.state.ssh_key.generate_key = generate
        self.state.ssh_key.key_path = Path(key_path) if key_path else None
        self.state.ssh_key.setup_authorized_keys = setup_auth

        self.clear_step_actions()

        if not generate:
            return

        key_path_str = key_path or str(Path.home() / ".ssh" / "id_ed25519")
        ssh_dir = str(Path(key_path_str).parent)
        user = os.environ.get("USER", "root")

        # Create .ssh directory
        self.state.actions.append(PlannedAction(
            action_type=ActionType.CREATE_DIR,
            description=f"Create SSH directory {ssh_dir}",
            target=ssh_dir,
            command=f"mkdir -p {ssh_dir}",
            requires_sudo=False,
            step_name=self.step_name,
        ))

        # Generate key
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

        # Set permissions
        self.state.actions.append(PlannedAction(
            action_type=ActionType.SET_PERMISSIONS,
            description="Set SSH directory permissions to 700",
            target=ssh_dir,
            permissions="700",
            command=f"chmod 700 {ssh_dir}",
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

        if setup_auth:
            auth_keys = str(Path(ssh_dir) / "authorized_keys")
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

            self.state.actions.append(PlannedAction(
                action_type=ActionType.SET_PERMISSIONS,
                description="Set authorized_keys permissions to 600",
                target=auth_keys,
                permissions="600",
                command=f'chmod 600 "{auth_keys}"',
                requires_sudo=False,
                step_name=self.step_name,
            ))
