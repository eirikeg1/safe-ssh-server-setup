from __future__ import annotations

import json
import os
import shlex
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from safe_ssh_setup.models import (
    ActionType,
    BackupManifest,
    PlannedAction,
    WizardState,
    ordered_actions,
)
from safe_ssh_setup.sudo import SudoHelper
from safe_ssh_setup.system import (
    listening_ports,
    target_uid_gid,
    target_user,
)

BACKUP_ROOT = Path("/var/backups/safe-ssh-setup")
SSHD_CONFIG = "/etc/ssh/sshd_config"

ProgressCallback = Callable[[int, int, PlannedAction, bool, str], None]


class ExecutionError(Exception):
    def __init__(self, action: PlannedAction, original_error: Exception) -> None:
        self.action = action
        self.original_error = original_error
        super().__init__(f"Failed: {action.description} — {original_error}")


class ActionExecutor:
    def __init__(self, state: WizardState, sudo: type[SudoHelper] = SudoHelper) -> None:
        self.state = state
        self.sudo = sudo
        self.backup_dir: Path | None = None
        self.manifest: BackupManifest | None = None
        self.aborted = False
        self.abort_reason = ""
        self.ssh_was_active = False

    # ---------------------------------------------------------------- backup

    def prepare_backup_dir(self) -> Path:
        """Create a unique backup directory and persist a rollback script now.

        The rollback script is written before any change is made, and rewritten
        as files are touched. If the process dies mid-apply, whatever was
        already modified is still recoverable.
        """
        base = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_dir = BACKUP_ROOT / base
        suffix = 1
        while self.sudo.file_exists(str(backup_dir)):
            suffix += 1
            backup_dir = BACKUP_ROOT / f"{base}-{suffix}"

        result = self.sudo.run(["mkdir", "-p", str(backup_dir)])
        if result.returncode != 0:
            raise ExecutionError(
                PlannedAction(
                    action_type=ActionType.CREATE_DIR,
                    description="Create backup directory",
                    target=str(backup_dir),
                ),
                RuntimeError(result.stderr.strip() or "mkdir failed"),
            )

        self.backup_dir = backup_dir
        self.state.backup_dir = backup_dir
        self.manifest = BackupManifest(
            timestamp=base,
            backup_dir=backup_dir,
            backed_up_files=[],
            created_files=[],
            rollback_script=backup_dir / "rollback.sh",
        )
        self._persist_recovery()
        return backup_dir

    def backup_file(self, filepath: str) -> str | None:
        """Back up a file, or record it as newly created when it doesn't exist.

        Returns the backup path, or None when there was nothing to back up.
        """
        assert self.backup_dir is not None

        if not self.sudo.file_exists(filepath):
            if self.manifest and filepath not in self.manifest.created_files:
                self.manifest.created_files.append(filepath)
                self._persist_recovery()
            return None

        relative = filepath.lstrip("/")
        backup_path = str(self.backup_dir / relative)
        backup_parent = str(Path(backup_path).parent)

        self.sudo.run(["mkdir", "-p", backup_parent])
        result = self.sudo.run(["cp", "-p", filepath, backup_path])
        if result.returncode != 0:
            return None

        if self.manifest:
            entry = (filepath, backup_path)
            if entry not in self.manifest.backed_up_files:
                self.manifest.backed_up_files.append(entry)
                self._persist_recovery()

        return backup_path

    def record_service(self, service: str) -> None:
        if self.manifest and service not in self.manifest.services_enabled:
            self.manifest.services_enabled.append(service)
            self._persist_recovery()

    # -------------------------------------------------------------- actions

    def execute_action(self, action: PlannedAction) -> tuple[bool, str]:
        """Execute a single action. Returns (success, message)."""
        try:
            handler = {
                ActionType.WRITE_FILE: self._write_file,
                ActionType.APPEND_AUTHORIZED_KEY: self._append_authorized_key,
                ActionType.GENERATE_SSH_KEY: self._generate_ssh_key,
                ActionType.VERIFY_SSH: self._verify_ssh,
            }.get(action.action_type, self._run_command)
            success, message = handler(action)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            success, message = False, str(exc)

        if not success and action.ignore_failure:
            return True, f"skipped ({message})"
        return success, message

    def _write_file(self, action: PlannedAction) -> tuple[bool, str]:
        self.backup_file(action.target)
        if action.content is None:
            return True, "no content, skipped"

        if action.requires_sudo:
            self.sudo.write_file(
                action.target,
                action.content,
                mode=action.permissions or "0644",
                owner=action.owner or "root:root",
            )
        else:
            path = Path(action.target)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(action.content)
            if action.permissions:
                os.chmod(path, int(action.permissions, 8))
            self._chown_to_target(path)
        return True, "OK"

    def _append_authorized_key(self, action: PlannedAction) -> tuple[bool, str]:
        """Append a public key to authorized_keys without invoking a shell."""
        key = (action.public_key or "").strip()

        # For generated keys the value does not exist until apply time.
        if not key and action.key_path:
            pub_path = Path(action.key_path + ".pub")
            try:
                key = pub_path.read_text().strip()
            except OSError as exc:
                return False, f"could not read {pub_path}: {exc}"

        if not key:
            return False, "no public key provided"

        path = Path(action.target)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._chown_to_target(path.parent)

        existing = path.read_text() if path.exists() else ""
        if any(line.strip() == key for line in existing.splitlines()):
            self._finalise_authorized_keys(path)
            return True, "key already present"

        needs_newline = bool(existing) and not existing.endswith("\n")
        with path.open("a", encoding="utf-8") as handle:
            if needs_newline:
                handle.write("\n")
            handle.write(key + "\n")

        self._finalise_authorized_keys(path)
        return True, "key added"

    def _finalise_authorized_keys(self, path: Path) -> None:
        os.chmod(path, 0o600)
        self._chown_to_target(path)
        os.chmod(path.parent, 0o700)
        self._chown_to_target(path.parent)

    def _generate_ssh_key(self, action: PlannedAction) -> tuple[bool, str]:
        key_path = Path(action.key_path or action.target)
        if key_path.exists():
            return True, "key already exists, skipped"

        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._chown_to_target(key_path.parent)

        result = self.sudo.run_as_user([
            "ssh-keygen",
            "-t", "ed25519",
            "-f", str(key_path),
            "-N", "",
            "-C", f"{target_user()}@safe-ssh-setup",
        ])
        if result.returncode != 0:
            return False, result.stderr.strip() or "ssh-keygen failed"

        if key_path.exists():
            os.chmod(key_path, 0o600)
            self._chown_to_target(key_path)
        pub_path = Path(str(key_path) + ".pub")
        if pub_path.exists():
            os.chmod(pub_path, 0o644)
            self._chown_to_target(pub_path)
        return True, "key generated"

    def _verify_ssh(self, action: PlannedAction) -> tuple[bool, str]:
        """Confirm sshd is actually up and listening before we firewall the box."""
        service = action.service or self.state.ssh_service
        port = action.port or self.state.ssh_config.port

        deadline = time.monotonic() + 20
        last = "not checked"
        while time.monotonic() < deadline:
            active = self.sudo.run(["systemctl", "is-active", service])
            if active.stdout.strip() == "active":
                if port in listening_ports():
                    return True, f"{service} active and listening on port {port}"
                last = f"{service} is active but nothing is listening on port {port}"
            else:
                last = f"{service} is not active ({active.stdout.strip() or 'unknown'})"
            time.sleep(1)

        return False, last

    def _run_command(self, action: PlannedAction) -> tuple[bool, str]:
        if not action.command:
            return True, "OK"

        runner = self.sudo.run if action.requires_sudo else self.sudo.run_as_user
        result = runner(action.command)

        if result.returncode not in action.ok_returncodes and action.fallback_command:
            result = runner(action.fallback_command)

        if result.returncode not in action.ok_returncodes:
            message = result.stderr.strip() or result.stdout.strip()
            return False, f"exit {result.returncode}: {message or 'command failed'}"

        if action.action_type == ActionType.ENABLE_SERVICE and action.target:
            self.record_service(action.target)

        return True, "OK"

    def _chown_to_target(self, path: Path) -> None:
        """Give a file back to the real user when we are running under sudo."""
        if os.geteuid() != 0:
            return
        try:
            uid, gid = target_uid_gid()
        except KeyError:
            return
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass

    # ------------------------------------------------------------ execution

    def execute_all(
        self,
        progress_callback: ProgressCallback | None = None,
    ) -> list[tuple[PlannedAction, bool, str]]:
        """Execute the whole plan in canonical order.

        A failing action marked ``critical`` restores sshd's original config,
        restarts it, and aborts the run — so the firewall is never locked down
        around an sshd that did not come back up.
        """
        if self.backup_dir is None:
            self.prepare_backup_dir()
        if not self.sudo.refresh_credentials():
            raise ExecutionError(
                PlannedAction(
                    action_type=ActionType.RUN_COMMAND,
                    description="Refresh sudo credentials",
                    target="sudo",
                ),
                RuntimeError(
                    "sudo credentials have expired. Restart safe-ssh-setup."
                ),
            )

        # Recorded before anything runs: aborting must not leave the daemon
        # running when it was stopped beforehand.
        self.ssh_was_active = self._service_is_active(self.state.ssh_service)

        actions = ordered_actions(self.state.actions)
        results: list[tuple[PlannedAction, bool, str]] = []
        total = len(actions)

        try:
            for index, action in enumerate(actions):
                if index % 5 == 0:
                    self.sudo.refresh_credentials()

                success, message = self.execute_action(action)
                results.append((action, success, message))
                if progress_callback:
                    progress_callback(index + 1, total, action, success, message)

                if not success and action.critical:
                    self.aborted = True
                    self.abort_reason = f"{action.description}: {message}"
                    restore_note = self._restore_sshd_config()
                    aborted_action = PlannedAction(
                        action_type=ActionType.RUN_COMMAND,
                        description="Abort and restore original SSH configuration",
                        target=self.state.ssh_service,
                        step_name=action.step_name,
                    )
                    results.append((aborted_action, True, restore_note))
                    if progress_callback:
                        progress_callback(
                            index + 1, total, aborted_action, True, restore_note
                        )
                    break
        finally:
            self._persist_recovery()
            self.state.applied = True
            self.state.apply_results = [
                (a.description, ok, msg) for a, ok, msg in results
            ]
            self.state.apply_succeeded = not self.aborted and all(
                ok for _, ok, _ in results
            )

        return results

    def _service_is_active(self, service: str) -> bool:
        return self.sudo.run(["systemctl", "is-active", service]).stdout.strip() == (
            "active"
        )

    def _restore_sshd_config(self) -> str:
        """Put the original sshd_config back and restore the daemon's state.

        "Restore" means the state the machine was in before the run. Restarting
        unconditionally would *start* a daemon that had been stopped, which on
        a first run also generates host keys and opens port 22 with the distro
        default config.
        """
        if not self.backup_dir:
            return "no backup directory; nothing restored"

        backup_path = self.backup_dir / SSHD_CONFIG.lstrip("/")
        if not self.sudo.file_exists(str(backup_path)):
            note = "no sshd_config backup existed; nothing restored"
        else:
            copied = self.sudo.run(["cp", "-p", str(backup_path), SSHD_CONFIG])
            if copied.returncode != 0:
                return f"restore FAILED: {copied.stderr.strip()}"
            note = "original sshd_config restored"

        service = self.state.ssh_service
        if self.ssh_was_active:
            result = self.sudo.run(["systemctl", "restart", service])
            if result.returncode != 0:
                return f"{note}, but restarting {service} failed: {result.stderr.strip()}"
            return f"{note} and {service} restarted"

        # It was not running before, so leave it that way.
        if self._service_is_active(service):
            result = self.sudo.run(["systemctl", "stop", service])
            if result.returncode != 0:
                return f"{note}, but stopping {service} failed: {result.stderr.strip()}"
            return f"{note}; {service} stopped (it was not running before)"
        return f"{note}; {service} left stopped as it was before"

    # ------------------------------------------------------------- recovery

    def _persist_recovery(self) -> None:
        """Write rollback.sh and manifest.json reflecting the current state."""
        if not self.manifest or not self.backup_dir:
            return
        try:
            self.sudo.write_file(
                str(self.backup_dir / "rollback.sh"),
                self._render_rollback_script(),
                mode="0755",
            )
            self.sudo.write_file(
                str(self.backup_dir / "manifest.json"),
                json.dumps(self._manifest_data(), indent=2) + "\n",
            )
        except Exception:  # noqa: BLE001 - recovery must never break the run
            pass

    def _manifest_data(self) -> dict:
        assert self.manifest is not None
        return {
            "timestamp": self.manifest.timestamp,
            "backup_dir": str(self.manifest.backup_dir),
            "backed_up_files": self.manifest.backed_up_files,
            "created_files": self.manifest.created_files,
            "services_enabled": self.manifest.services_enabled,
            "ssh_service": self.state.ssh_service,
            "ssh_port": self.state.ssh_config.port,
        }

    def _services_to_restart(self) -> list[str]:
        assert self.manifest is not None
        services: set[str] = set()
        for original, _ in self.manifest.backed_up_files:
            services.update(self._services_for_path(original))
        for created in self.manifest.created_files:
            services.update(self._services_for_path(created))
        return sorted(services)

    def _services_for_path(self, path: str) -> set[str]:
        services: set[str] = set()
        if path.startswith("/etc/ssh/"):
            services.add(self.state.ssh_service)
        if "fail2ban" in path:
            services.add("fail2ban")
        if "knockd" in path:
            services.add("knockd")
        return services

    def _render_rollback_script(self) -> str:
        assert self.manifest is not None

        lines = [
            "#!/bin/bash",
            "# Rollback script generated by safe-ssh-setup",
            f"# Backup timestamp: {self.manifest.timestamp}",
            "#",
            "# Restores every file this run modified and deletes every file it",
            "# created. Run with: sudo bash rollback.sh",
            "",
            # Deliberately not `set -e`: a recovery script must keep going and
            # restore as much as it can rather than stop at the first error.
            "set -u",
            "",
            'if [ "$(id -u)" -ne 0 ]; then',
            '  echo "This script must be run as root (use sudo)." >&2',
            "  exit 1",
            "fi",
            "",
        ]

        if self.manifest.backed_up_files:
            lines.append('echo "Restoring modified files..."')
            for original, backup in self.manifest.backed_up_files:
                src = shlex.quote(backup)
                dst = shlex.quote(original)
                lines.append(
                    f"if cp -p {src} {dst}; then "
                    f'echo "  restored: {original}"; '
                    f'else echo "  FAILED:   {original}" >&2; fi'
                )
            lines.append("")

        if self.manifest.created_files:
            lines.append('echo "Removing files created by safe-ssh-setup..."')
            for created in self.manifest.created_files:
                quoted = shlex.quote(created)
                lines.append(
                    f"if [ -e {quoted} ]; then rm -f {quoted} && "
                    f'echo "  removed:  {created}"; fi'
                )
            lines.append("")

        services = self._services_to_restart()
        if services:
            lines.append('echo "Restarting services..."')
            for service in services:
                quoted = shlex.quote(service)
                lines.append(
                    f"systemctl restart {quoted} 2>/dev/null && "
                    f'echo "  restarted: {service}" || '
                    f'echo "  could not restart: {service}" >&2'
                )
            lines.append("")

        lines.extend([
            'echo ""',
            'echo "Rollback complete."',
            'echo ""',
            'echo "NOT reverted automatically — undo these by hand if needed:"',
            'echo "  - firewall rules (ufw/firewalld) and the default zone policy"',
        ])
        if self.manifest.services_enabled:
            enabled = ", ".join(self.manifest.services_enabled)
            lines.append(
                f'echo "  - services enabled at boot: {enabled}"'
            )
        if self.state.ssh_config.port != 22:
            lines.append(
                'echo "  - SELinux port label: '
                f'semanage port -d -t ssh_port_t -p tcp {self.state.ssh_config.port}"'
            )
        lines.append('echo "  - packages installed by the wizard"')

        return "\n".join(lines) + "\n"
