"""Standalone rollback entry point.

Usage: python -m safe_ssh_setup.rollback /var/backups/safe-ssh-setup/YYYYMMDD-HHMMSS/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from safe_ssh_setup.sudo import SudoHelper

BACKUP_ROOT = Path("/var/backups/safe-ssh-setup")


def _services_for_path(path: str, ssh_service: str) -> set[str]:
    services: set[str] = set()
    if path.startswith("/etc/ssh/"):
        services.add(ssh_service)
    if "fail2ban" in path:
        services.add("fail2ban")
    if "knockd" in path:
        services.add("knockd")
    return services


def rollback(backup_dir: str) -> int:
    backup_path = Path(backup_dir)

    if not backup_path.exists():
        print(f"Error: Backup directory not found: {backup_dir}")
        return 1

    if not SudoHelper.check_sudo_available():
        # Every restore below needs root; prompt now rather than failing
        # halfway through with an invisible password prompt.
        print("Rollback needs sudo access.")
        if not SudoHelper.prompt_sudo():
            print("Error: could not obtain sudo credentials.")
            return 1

    manifest_file = backup_path / "manifest.json"
    if not manifest_file.exists():
        print(f"Error: No manifest.json found in {backup_dir}")
        print("Try running the rollback script directly instead:")
        print(f"  sudo bash {backup_path}/rollback.sh")
        return 1

    with open(manifest_file) as f:
        manifest = json.load(f)

    backed_up_files = manifest.get("backed_up_files", [])
    created_files = manifest.get("created_files", [])
    ssh_service = manifest.get("ssh_service", "sshd")

    if not backed_up_files and not created_files:
        print("Nothing to roll back.")
        return 0

    services: set[str] = set()
    failures = 0

    if backed_up_files:
        print(f"Restoring {len(backed_up_files)} modified file(s)...")
        for original, backup in backed_up_files:
            result = SudoHelper.run(["cp", "-p", backup, original])
            if result.returncode == 0:
                print(f"  restored: {original}")
                services |= _services_for_path(original, ssh_service)
            else:
                failures += 1
                print(f"  FAILED:   {original} — {result.stderr.strip()}")

    if created_files:
        # Files that did not exist before this run must be removed, otherwise
        # "rollback" leaves the new configuration in place.
        print(f"\nRemoving {len(created_files)} created file(s)...")
        for created in created_files:
            result = SudoHelper.run(["rm", "-f", created])
            if result.returncode == 0:
                print(f"  removed:  {created}")
                services |= _services_for_path(created, ssh_service)
            else:
                failures += 1
                print(f"  FAILED:   {created} — {result.stderr.strip()}")

    if services:
        print("\nRestarting services...")
        for service in sorted(services):
            result = SudoHelper.run(["systemctl", "restart", service])
            if result.returncode == 0:
                print(f"  restarted: {service}")
            else:
                print(f"  could not restart: {service}")

    print("\nRollback complete.")
    print("\nNOT reverted automatically — undo these by hand if needed:")
    print("  - firewall rules (ufw/firewalld) and the default zone policy")
    enabled = manifest.get("services_enabled") or []
    if enabled:
        print(f"  - services enabled at boot: {', '.join(enabled)}")
    port = manifest.get("ssh_port")
    if port and port != 22:
        print(
            "  - SELinux port label: "
            f"semanage port -d -t ssh_port_t -p tcp {port}"
        )
    print("  - packages installed by the wizard")

    return 1 if failures else 0


def list_backups() -> None:
    print("Available backups:")
    if BACKUP_ROOT.exists():
        entries = sorted(d for d in BACKUP_ROOT.iterdir() if d.is_dir())
        if entries:
            for entry in entries:
                print(f"  {entry}")
            return
    print("  (none found)")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m safe_ssh_setup.rollback",
        description="Restore a safe-ssh-setup backup.",
    )
    parser.add_argument(
        "backup_directory",
        nargs="?",
        help="backup directory to restore; omit to list available backups",
    )
    args = parser.parse_args(argv)

    if not args.backup_directory:
        list_backups()
        sys.exit(1)

    sys.exit(rollback(args.backup_directory))


if __name__ == "__main__":
    main()
