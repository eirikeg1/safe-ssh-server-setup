"""Standalone rollback entry point.

Usage: python -m safe_ssh_setup.rollback /var/backups/safe-ssh-setup/YYYYMMDD-HHMMSS/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from safe_ssh_setup.sudo import SudoHelper


def rollback(backup_dir: str) -> None:
    backup_path = Path(backup_dir)

    if not backup_path.exists():
        print(f"Error: Backup directory not found: {backup_dir}")
        sys.exit(1)

    manifest_file = backup_path / "manifest.json"
    if not manifest_file.exists():
        print(f"Error: No manifest.json found in {backup_dir}")
        print("Try running the rollback.sh script directly instead:")
        print(f"  sudo bash {backup_path}/rollback.sh")
        sys.exit(1)

    with open(manifest_file) as f:
        manifest = json.load(f)

    backed_up_files = manifest.get("backed_up_files", [])

    if not backed_up_files:
        print("No files to restore.")
        return

    print(f"Restoring {len(backed_up_files)} file(s) from backup...")

    services_to_restart = set()

    for original, backup in backed_up_files:
        try:
            SudoHelper.run(f'cp -p "{backup}" "{original}"')
            print(f"  Restored: {original}")

            if "ssh" in original:
                # Try both service names — one will exist
                services_to_restart.add("ssh")
                services_to_restart.add("sshd")
            if "fail2ban" in original:
                services_to_restart.add("fail2ban")
            if "knockd" in original:
                services_to_restart.add("knockd")
        except Exception as e:
            print(f"  FAILED: {original} — {e}")

    if services_to_restart:
        print("\nRestarting services...")
        for svc in sorted(services_to_restart):
            try:
                SudoHelper.run(f"systemctl restart {svc}")
                print(f"  Restarted: {svc}")
            except Exception:
                print(f"  Failed to restart: {svc}")

    print("\nRollback complete.")


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m safe_ssh_setup.rollback <backup_directory>")
        print("\nAvailable backups:")
        backup_base = Path("/var/backups/safe-ssh-setup")
        if backup_base.exists():
            for d in sorted(backup_base.iterdir()):
                if d.is_dir():
                    print(f"  {d}")
        else:
            print("  (none found)")
        sys.exit(1)

    rollback(sys.argv[1])


if __name__ == "__main__":
    main()
