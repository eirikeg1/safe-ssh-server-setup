from __future__ import annotations

from datetime import datetime

from jinja2 import Environment, PackageLoader
from textual.app import ComposeResult
from textual.widgets import Collapsible, Input, Label, Static, Switch

from safe_ssh_setup.models import ActionType, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.sudo import SudoHelper


class SSHHardeningScreen(WizardScreen):
    step_name = "ssh_hardening"

    def compose_step(self) -> ComposeResult:
        yield Static("SSH Daemon Hardening", classes="section-header")
        yield Static(
            "Configure sshd for maximum security. "
            "Key-only authentication is enabled by default.",
            classes="section-description",
        )

        # Authentication
        yield Static("Authentication", classes="section-header")

        yield Label("Key-only authentication (disable passwords)")
        yield Switch(value=True, id="key-only-auth")

        yield Label("Disable root login")
        yield Switch(value=True, id="disable-root")

        yield Label("Disable empty passwords")
        yield Switch(value=True, id="disable-empty-pw")

        yield Label("Disable keyboard-interactive auth")
        yield Switch(value=True, id="disable-kbd")

        # Limits
        yield Static("Connection Limits", classes="section-header")

        yield Label("Max authentication tries:")
        yield Input(value="3", id="max-auth-tries", type="integer")

        yield Label("Login grace time (seconds):")
        yield Input(value="30", id="login-grace-time", type="integer")

        yield Label("Client alive interval (seconds):")
        yield Input(value="300", id="alive-interval", type="integer")

        yield Label("Client alive count max:")
        yield Input(value="2", id="alive-count", type="integer")

        # Forwarding
        yield Static("Forwarding", classes="section-header")

        yield Label("Allow X11 forwarding")
        yield Switch(value=False, id="x11-fwd")

        yield Label("Allow agent forwarding")
        yield Switch(value=False, id="agent-fwd")

        yield Label("Allow TCP forwarding")
        yield Switch(value=False, id="tcp-fwd")

        # Cryptography
        with Collapsible(title="Advanced: Cryptography Settings"):
            yield Static(
                "Strong defaults are pre-selected. Only change these "
                "if you know what you're doing.",
                classes="section-description",
            )
            yield Label("Ciphers (comma-separated):")
            yield Input(
                value=",".join(self.state.ssh_config.ciphers),
                id="ciphers",
            )
            yield Label("MACs (comma-separated):")
            yield Input(
                value=",".join(self.state.ssh_config.macs),
                id="macs",
            )
            yield Label("Key exchange algorithms (comma-separated):")
            yield Input(
                value=",".join(self.state.ssh_config.kex_algorithms),
                id="kex",
            )

    def validate_step(self) -> str | None:
        try:
            mat = int(self.query_one("#max-auth-tries", Input).value or "0")
            lgt = int(self.query_one("#login-grace-time", Input).value or "0")
            cai = int(self.query_one("#alive-interval", Input).value or "0")
            cac = int(self.query_one("#alive-count", Input).value or "0")
        except ValueError:
            return "All numeric values must be valid numbers."
        if mat < 1:
            return "Max auth tries must be at least 1."
        if lgt < 1:
            return "Login grace time must be at least 1 second."
        if cai < 0:
            return "Client alive interval cannot be negative."
        if cac < 0:
            return "Client alive count cannot be negative."
        return None

    def save_state(self) -> None:
        cfg = self.state.ssh_config

        key_only = self.query_one("#key-only-auth", Switch).value
        cfg.pubkey_authentication = True
        cfg.password_authentication = not key_only
        cfg.kbd_interactive_auth = not self.query_one("#disable-kbd", Switch).value
        cfg.permit_root_login = (
            "no" if self.query_one("#disable-root", Switch).value else "yes"
        )
        cfg.permit_empty_passwords = not self.query_one(
            "#disable-empty-pw", Switch
        ).value

        cfg.max_auth_tries = int(
            self.query_one("#max-auth-tries", Input).value or "3"
        )
        cfg.login_grace_time = int(
            self.query_one("#login-grace-time", Input).value or "30"
        )
        cfg.client_alive_interval = int(
            self.query_one("#alive-interval", Input).value or "300"
        )
        cfg.client_alive_count_max = int(
            self.query_one("#alive-count", Input).value or "2"
        )

        cfg.x11_forwarding = self.query_one("#x11-fwd", Switch).value
        cfg.allow_agent_forwarding = self.query_one("#agent-fwd", Switch).value
        cfg.allow_tcp_forwarding = self.query_one("#tcp-fwd", Switch).value

        ciphers_str = self.query_one("#ciphers", Input).value
        if ciphers_str:
            cfg.ciphers = [c.strip() for c in ciphers_str.split(",") if c.strip()]

        macs_str = self.query_one("#macs", Input).value
        if macs_str:
            cfg.macs = [m.strip() for m in macs_str.split(",") if m.strip()]

        kex_str = self.query_one("#kex", Input).value
        if kex_str:
            cfg.kex_algorithms = [k.strip() for k in kex_str.split(",") if k.strip()]

        # Generate sshd_config
        self.clear_step_actions()

        env = Environment(
            loader=PackageLoader("safe_ssh_setup", "templates"),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("sshd_config.j2")
        new_content = template.render(
            ssh=cfg,
            timestamp=datetime.now().isoformat(),
        )

        original = SudoHelper.read_file("/etc/ssh/sshd_config") or ""

        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Write hardened sshd_config",
            target="/etc/ssh/sshd_config",
            content=new_content,
            original_content=original,
            requires_sudo=True,
            step_name=self.step_name,
        ))

        svc = self.state.ssh_service

        self.state.actions.append(PlannedAction(
            action_type=ActionType.CREATE_DIR,
            description="Create sshd privilege separation directory",
            target="/run/sshd",
            command="mkdir -p /run/sshd",
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Validate sshd_config syntax",
            target=svc,
            command="sshd -t -f /etc/ssh/sshd_config",
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.ENABLE_SERVICE,
            description="Enable SSH daemon to start at boot",
            target=svc,
            command=f"systemctl enable {svc}",
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RESTART_SERVICE,
            description="Restart SSH daemon",
            target=svc,
            command=f"systemctl restart {svc}",
            requires_sudo=True,
            step_name=self.step_name,
        ))
