from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Callable

from safe_ssh_setup.models import (
    ActionType,
    BackupManifest,
    PlannedAction,
    WizardState,
)
from safe_ssh_setup.sudo import SudoHelper


class ExecutionError(Exception):
    def __init__(self, action: PlannedAction, original_error: Exception) -> None:
        self.action = action
        self.original_error = original_error
        super().__init__(f"Failed: {action.description} — {original_error}")


class ActionExecutor:
    def __init__(self, state: WizardState) -> None:
        self.state = state
        self.backup_dir: Path | None = None
        self.manifest: BackupManifest | None = None

    def prepare_backup_dir(self) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_dir = Path(f"/var/backups/safe-ssh-setup/{timestamp}")
        SudoHelper.run(f"mkdir -p {backup_dir}")
        self.backup_dir = backup_dir
        self.state.backup_dir = backup_dir
        self.manifest = BackupManifest(
            timestamp=timestamp,
            backup_dir=backup_dir,
            backed_up_files=[],
            rollback_script=backup_dir / "rollback.sh",
        )
        return backup_dir

    def backup_file(self, filepath: str) -> str | None:
        """Back up a file. Returns the backup path, or None if file doesn't exist."""
        result = SudoHelper.run(f'test -f "{filepath}"', check=False)
        if result.returncode != 0:
            return None

        assert self.backup_dir is not None
        # Preserve directory structure in backup
        relative = filepath.lstrip("/")
        backup_path = str(self.backup_dir / relative)
        backup_parent = str(Path(backup_path).parent)

        SudoHelper.run(f'mkdir -p "{backup_parent}"')
        SudoHelper.run(f'cp -p "{filepath}" "{backup_path}"')

        if self.manifest:
            self.manifest.backed_up_files.append((filepath, backup_path))

        return backup_path

    def execute_action(self, action: PlannedAction) -> tuple[bool, str]:
        """Execute a single action. Returns (success, message)."""
        try:
            if action.action_type == ActionType.WRITE_FILE:
                # Back up original
                self.backup_file(action.target)
                # Write new content
                if action.content is not None:
                    if action.requires_sudo:
                        SudoHelper.write_file(
                            action.target,
                            action.content,
                            mode=action.permissions or "0644",
                            owner=action.owner or "root:root",
                        )
                    else:
                        Path(action.target).parent.mkdir(parents=True, exist_ok=True)
                        Path(action.target).write_text(action.content)
                        if action.permissions:
                            import os
                            os.chmod(action.target, int(action.permissions, 8))

            elif action.action_type in (
                ActionType.RUN_COMMAND,
                ActionType.INSTALL_PACKAGE,
                ActionType.ENABLE_SERVICE,
                ActionType.RESTART_SERVICE,
                ActionType.CREATE_DIR,
                ActionType.SET_PERMISSIONS,
            ):
                if action.command:
                    if action.requires_sudo:
                        result = SudoHelper.run(action.command, check=False)
                    else:
                        result = SudoHelper.run_no_sudo(action.command, check=False)
                    if result.returncode != 0:
                        error_msg = result.stderr.strip() or result.stdout.strip()
                        return False, f"Command failed: {error_msg}"

            return True, "OK"

        except Exception as e:
            return False, str(e)

    def execute_all(
        self,
        progress_callback: Callable[[int, int, PlannedAction, bool, str], None],
    ) -> list[tuple[PlannedAction, bool, str]]:
        """Execute all planned actions.

        Args:
            progress_callback: Called after each action with
                (current_index, total, action, success, message)

        Returns:
            List of (action, success, message) tuples.
        """
        self.prepare_backup_dir()
        SudoHelper.refresh_credentials()

        results: list[tuple[PlannedAction, bool, str]] = []
        total = len(self.state.actions)

        for i, action in enumerate(self.state.actions):
            # Refresh sudo credentials periodically
            if i % 5 == 0:
                SudoHelper.refresh_credentials()

            success, message = self.execute_action(action)
            results.append((action, success, message))
            progress_callback(i + 1, total, action, success, message)

            # If sshd_config validation fails, restore immediately
            if (
                not success
                and action.target == "sshd"
                and "Validate" in action.description
            ):
                self._restore_sshd_config()
                break

        # Generate rollback script
        self._generate_rollback_script()
        self._save_manifest()

        self.state.applied = True
        return results

    def _restore_sshd_config(self) -> None:
        """Restore the original sshd_config from backup."""
        if not self.backup_dir:
            return
        backup_path = self.backup_dir / "etc/ssh/sshd_config"
        result = SudoHelper.run(
            f'test -f "{backup_path}"', check=False
        )
        if result.returncode == 0:
            SudoHelper.run(
                f'cp -p "{backup_path}" /etc/ssh/sshd_config'
            )

    def _generate_rollback_script(self) -> None:
        """Generate a bash script that restores all backed-up files."""
        if not self.manifest or not self.backup_dir:
            return

        lines = [
            "#!/bin/bash",
            "# Rollback script generated by safe-ssh-setup",
            f"# Backup timestamp: {self.manifest.timestamp}",
            "set -e",
            "",
            'echo "Restoring backed-up files..."',
        ]

        services_to_restart = set()

        for original, backup in self.manifest.backed_up_files:
            lines.append(f'cp -p "{backup}" "{original}"')
            lines.append(f'echo "  Restored: {original}"')

            if "sshd" in original:
                services_to_restart.add("sshd")
            if "fail2ban" in original:
                services_to_restart.add("fail2ban")
            if "knockd" in original:
                services_to_restart.add("knockd")

        if services_to_restart:
            lines.append("")
            lines.append('echo "Restarting services..."')
            for svc in sorted(services_to_restart):
                lines.append(f"systemctl restart {svc} 2>/dev/null || true")

        lines.append("")
        lines.append('echo "Rollback complete."')

        script = "\n".join(lines) + "\n"
        script_path = str(self.backup_dir / "rollback.sh")
        SudoHelper.write_file(script_path, script, mode="0755")

    def _save_manifest(self) -> None:
        """Save the backup manifest as JSON."""
        if not self.manifest or not self.backup_dir:
            return

        manifest_data = {
            "timestamp": self.manifest.timestamp,
            "backup_dir": str(self.manifest.backup_dir),
            "backed_up_files": self.manifest.backed_up_files,
        }
        content = json.dumps(manifest_data, indent=2)
        manifest_path = str(self.backup_dir / "manifest.json")
        SudoHelper.write_file(manifest_path, content)
