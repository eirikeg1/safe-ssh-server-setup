from __future__ import annotations

from datetime import datetime

from jinja2 import Environment, PackageLoader
from textual.app import ComposeResult
from textual.widgets import Collapsible, Input, Label, Static, Switch

from safe_ssh_setup.distro import (
    PackageManager,
    selinux_port_fallback,
    selinux_port_steps,
)
from safe_ssh_setup.models import ActionType, DistroFamily, PlannedAction
from safe_ssh_setup.screens.base import WizardScreen
from safe_ssh_setup.sudo import SudoHelper
from safe_ssh_setup.system import selinux_enabled, sftp_server_path
from safe_ssh_setup.validation import (
    ValidationError,
    validate_algorithm_list,
    validate_non_negative,
    validate_positive,
)


def build_environment() -> Environment:
    return Environment(
        loader=PackageLoader("safe_ssh_setup", "templates"),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )


class SSHHardeningScreen(WizardScreen):
    step_name = "ssh_hardening"

    def compose_step(self) -> ComposeResult:
        cfg = self.state.ssh_config

        yield Static("SSH Daemon Hardening", classes="section-header")
        yield Static(
            "Configure sshd for maximum security. "
            "Key-only authentication is enabled by default.",
            classes="section-description",
        )

        yield Static("Authentication", classes="section-header")

        yield Label("Key-only authentication (disable passwords)")
        yield Switch(value=not cfg.password_authentication, id="key-only-auth")

        yield Label("Disable root login")
        yield Switch(value=cfg.permit_root_login == "no", id="disable-root")

        yield Label("Disable empty passwords")
        yield Switch(value=not cfg.permit_empty_passwords, id="disable-empty-pw")

        yield Label("Disable keyboard-interactive auth")
        yield Switch(value=not cfg.kbd_interactive_auth, id="disable-kbd")

        yield Static("Connection Limits", classes="section-header")

        yield Label("Max authentication tries:")
        yield Input(value=str(cfg.max_auth_tries), id="max-auth-tries", type="integer")

        yield Label("Login grace time (seconds):")
        yield Input(
            value=str(cfg.login_grace_time), id="login-grace-time", type="integer"
        )

        yield Label("Client alive interval (seconds):")
        yield Input(
            value=str(cfg.client_alive_interval), id="alive-interval", type="integer"
        )

        yield Label("Client alive count max:")
        yield Input(
            value=str(cfg.client_alive_count_max), id="alive-count", type="integer"
        )

        yield Static("Forwarding", classes="section-header")

        yield Label("Allow X11 forwarding")
        yield Switch(value=cfg.x11_forwarding, id="x11-fwd")

        yield Label("Allow agent forwarding")
        yield Switch(value=cfg.allow_agent_forwarding, id="agent-fwd")

        yield Label("Allow TCP forwarding")
        yield Switch(value=cfg.allow_tcp_forwarding, id="tcp-fwd")

        with Collapsible(title="Advanced: Cryptography Settings"):
            yield Static(
                "Strong defaults are pre-selected. Only change these "
                "if you know what you're doing.",
                classes="section-description",
            )
            yield Label("Ciphers (comma-separated):")
            yield Input(value=",".join(cfg.ciphers), id="ciphers")
            yield Label("MACs (comma-separated):")
            yield Input(value=",".join(cfg.macs), id="macs")
            yield Label("Key exchange algorithms (comma-separated):")
            yield Input(value=",".join(cfg.kex_algorithms), id="kex")

    def validate_step(self) -> str | None:
        try:
            validate_positive(
                self.query_one("#max-auth-tries", Input).value, "Max auth tries"
            )
            validate_positive(
                self.query_one("#login-grace-time", Input).value, "Login grace time"
            )
            validate_non_negative(
                self.query_one("#alive-interval", Input).value,
                "Client alive interval",
            )
            validate_non_negative(
                self.query_one("#alive-count", Input).value, "Client alive count"
            )
            validate_algorithm_list(self.query_one("#ciphers", Input).value, "Ciphers")
            validate_algorithm_list(self.query_one("#macs", Input).value, "MACs")
            validate_algorithm_list(
                self.query_one("#kex", Input).value, "Key exchange algorithms"
            )
        except ValidationError as e:
            return str(e)
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

        cfg.max_auth_tries = validate_positive(
            self.query_one("#max-auth-tries", Input).value, "Max auth tries"
        )
        cfg.login_grace_time = validate_positive(
            self.query_one("#login-grace-time", Input).value, "Login grace time"
        )
        cfg.client_alive_interval = validate_non_negative(
            self.query_one("#alive-interval", Input).value, "Client alive interval"
        )
        cfg.client_alive_count_max = validate_non_negative(
            self.query_one("#alive-count", Input).value, "Client alive count"
        )

        cfg.x11_forwarding = self.query_one("#x11-fwd", Switch).value
        cfg.allow_agent_forwarding = self.query_one("#agent-fwd", Switch).value
        cfg.allow_tcp_forwarding = self.query_one("#tcp-fwd", Switch).value

        cfg.ciphers = validate_algorithm_list(
            self.query_one("#ciphers", Input).value, "Ciphers"
        )
        cfg.macs = validate_algorithm_list(
            self.query_one("#macs", Input).value, "MACs"
        )
        cfg.kex_algorithms = validate_algorithm_list(
            self.query_one("#kex", Input).value, "Key exchange algorithms"
        )

        self.clear_step_actions()

        distro = self.state.distro_info
        svc = self.state.ssh_service
        port = cfg.port

        template = build_environment().get_template("sshd_config.j2")
        new_content = template.render(
            ssh=cfg,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            # Resolved per system: sshd -t does not verify this path exists,
            # so a wrong one silently breaks sftp and scp.
            sftp_server=sftp_server_path(),
            sshd_config_dir=distro.sshd_config_dir if distro else "/etc/ssh/sshd_config.d",
        )

        original = SudoHelper.read_file("/etc/ssh/sshd_config") or ""

        # SELinux must know about the port before sshd tries to bind it.
        if (
            distro
            and distro.family == DistroFamily.RHEL
            and selinux_enabled()
            and port != 22
        ):
            pm = PackageManager(distro)
            self.state.actions.append(PlannedAction(
                action_type=ActionType.INSTALL_PACKAGE,
                description="Install SELinux management tools",
                target="selinux-tools",
                command=pm.install_command(["selinux-tools"]),
                requires_sudo=True,
                step_name=self.step_name,
            ))
            for step in selinux_port_steps(port):
                self.state.actions.append(PlannedAction(
                    action_type=ActionType.RUN_COMMAND,
                    description=step.description,
                    target="selinux",
                    command=step.argv,
                    # -a fails when the port is already defined; -m updates it.
                    fallback_command=selinux_port_fallback(port),
                    requires_sudo=True,
                    critical=True,
                    step_name=self.step_name,
                ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.WRITE_FILE,
            description="Write hardened sshd_config",
            target="/etc/ssh/sshd_config",
            content=new_content,
            original_content=original,
            permissions="0600",
            requires_sudo=True,
            critical=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.CREATE_DIR,
            description="Create sshd privilege separation directory",
            target="/run/sshd",
            command=["mkdir", "-p", "/run/sshd"],
            requires_sudo=True,
            step_name=self.step_name,
        ))

        # sshd -t refuses to run without host keys, and on a machine where the
        # daemon has never been started they do not exist yet: they are
        # normally created by sshd.service on first start. ssh-keygen -A is
        # idempotent and only creates the types that are missing.
        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Generate missing SSH host keys",
            target=svc,
            command=["ssh-keygen", "-A"],
            requires_sudo=True,
            critical=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RUN_COMMAND,
            description="Validate sshd_config syntax",
            target=svc,
            command=["sshd", "-t", "-f", "/etc/ssh/sshd_config"],
            requires_sudo=True,
            critical=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.ENABLE_SERVICE,
            description="Enable SSH daemon to start at boot",
            target=svc,
            command=["systemctl", "enable", svc],
            requires_sudo=True,
            step_name=self.step_name,
        ))

        self.state.actions.append(PlannedAction(
            action_type=ActionType.RESTART_SERVICE,
            description="Restart SSH daemon",
            target=svc,
            command=["systemctl", "restart", svc],
            requires_sudo=True,
            critical=True,
            step_name=self.step_name,
        ))

        # Confirm sshd actually came back before the firewall locks the box.
        self.state.actions.append(PlannedAction(
            action_type=ActionType.VERIFY_SSH,
            description=f"Verify SSH daemon is listening on port {port}",
            target=svc,
            service=svc,
            port=port,
            requires_sudo=True,
            critical=True,
            step_name=self.step_name,
        ))
