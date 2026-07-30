from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.widgets import Input, Label, RadioButton, RadioSet, Static, TextArea

from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.system import read_authorized_keys, target_home, target_user
from safe_ssh_setup.validation import (
    ValidationError,
    authorized_keys_has_key,
    validate_public_key,
)


class SSHKeyScreen(WizardScreen):
    step_name = "ssh_key"

    def compose_step(self) -> ComposeResult:
        user = target_user()
        home = target_home()

        yield Static("SSH Key Setup", classes="section-header")
        yield Static(
            "To connect securely, your client machine's public key must be "
            f"added to {home}/.ssh/authorized_keys on this server "
            f"(user: {user}).",
            classes="section-description",
        )

        if authorized_keys_has_key(read_authorized_keys()):
            yield Static(
                f"{user} already has at least one key in authorized_keys. "
                "You can skip this step if that key is the one you use.",
                classes="section-description",
            )

        mode = self.state.ssh_key.mode

        yield RadioSet(
            RadioButton(
                "Paste a public key from my client (recommended)",
                id="radio-paste",
                value=mode != "generate",
            ),
            RadioButton(
                "Generate a new key pair on this server",
                id="radio-generate",
                value=mode == "generate",
            ),
            id="key-mode",
        )

        yield Static(
            "\nOn your client machine, run:\n"
            "  cat ~/.ssh/id_ed25519.pub\n\n"
            "Then paste the single line of output below:",
            classes="section-description",
            id="paste-instructions",
        )
        yield TextArea(self.state.ssh_key.public_key, id="pubkey-input")

        yield Static(
            "Generating the key here puts an unencrypted private key on the "
            "server you are hardening. You must copy it to your client and "
            "delete it from the server afterwards. Pasting a key from your "
            "client is safer.",
            classes="summary-warning",
            id="generate-warning",
        )
        yield Label("Key path:", id="keypath-label")
        yield Input(
            value=str(self.state.ssh_key.key_path or (home / ".ssh" / "id_ed25519")),
            id="key-path",
        )

    def on_mount(self) -> None:
        self._update_mode_visibility()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self._update_mode_visibility()

    def _update_mode_visibility(self) -> None:
        is_paste = self._is_paste_mode()
        self.query_one("#paste-instructions").display = is_paste
        self.query_one("#pubkey-input").display = is_paste
        self.query_one("#generate-warning").display = not is_paste
        self.query_one("#keypath-label").display = not is_paste
        key_path = self.query_one("#key-path", Input)
        key_path.display = not is_paste
        key_path.disabled = is_paste

    def _is_paste_mode(self) -> bool:
        radio_set = self.query_one("#key-mode", RadioSet)
        pressed = radio_set.pressed_button
        return pressed is None or pressed.id == "radio-paste"

    def _key_path(self) -> Path:
        raw = (self.query_one("#key-path", Input).value or "").strip()
        if not raw:
            return target_home() / ".ssh" / "id_ed25519"
        # "~" is not expanded by anything downstream, so expand it here rather
        # than creating a directory literally named "~".
        return Path(raw).expanduser()

    def validate_step(self) -> str | None:
        if self._is_paste_mode():
            try:
                validate_public_key(self.query_one("#pubkey-input", TextArea).text)
            except ValidationError as e:
                return str(e)
            return None

        path = self._key_path()
        if not path.is_absolute():
            return f"Key path must be an absolute path (got {path})."
        if path.exists() and not path.is_file():
            return f"Key path exists and is not a file: {path}"
        return None

    def save_state(self) -> None:
        self.clear_step_actions()

        ssh_dir = target_home() / ".ssh"
        auth_keys = ssh_dir / "authorized_keys"

        # All of these run as the invoking user and are performed natively by
        # the executor — no shell, so no value here can be interpreted as code.
        self.state.actions.append(PlannedAction(
            action_type=ActionType.CREATE_DIR,
            description=f"Create SSH directory {ssh_dir} (mode 700)",
            target=str(ssh_dir),
            command=["mkdir", "-p", "-m", "700", str(ssh_dir)],
            permissions="700",
            requires_sudo=False,
            step_name=self.step_name,
        ))

        if self._is_paste_mode():
            public_key = validate_public_key(
                self.query_one("#pubkey-input", TextArea).text
            )
            self.state.ssh_key.mode = "paste"
            self.state.ssh_key.public_key = public_key
            self.state.ssh_key.setup_authorized_keys = True

            self.state.actions.append(PlannedAction(
                action_type=ActionType.APPEND_AUTHORIZED_KEY,
                description="Add client public key to authorized_keys",
                target=str(auth_keys),
                public_key=public_key,
                permissions="600",
                requires_sudo=False,
                critical=True,
                step_name=self.step_name,
            ))
            return

        key_path = self._key_path()
        self.state.ssh_key.mode = "generate"
        self.state.ssh_key.key_path = key_path

        self.state.actions.append(PlannedAction(
            action_type=ActionType.GENERATE_SSH_KEY,
            description=f"Generate Ed25519 SSH key at {key_path}",
            target=str(key_path),
            key_path=str(key_path),
            requires_sudo=False,
            critical=True,
            step_name=self.step_name,
        ))

        # The key does not exist until apply time, so the executor reads
        # <key_path>.pub itself rather than baking a value in now.
        self.state.actions.append(PlannedAction(
            action_type=ActionType.APPEND_AUTHORIZED_KEY,
            description="Add generated public key to authorized_keys",
            target=str(auth_keys),
            key_path=str(key_path),
            permissions="600",
            requires_sudo=False,
            critical=True,
            step_name=self.step_name,
        ))

    def skip_step(self) -> None:
        super().skip_step()
        self.state.ssh_key.public_key = ""
