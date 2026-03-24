"""Disable SSH and related services."""

from __future__ import annotations

import sys

from safe_ssh_setup.sudo import SudoHelper

# Try both ssh service names — Debian uses "ssh", Fedora uses "sshd"
SERVICES = ["ssh", "sshd", "fail2ban", "knockd"]


def _is_active(service: str) -> bool:
    result = SudoHelper.run(f"systemctl is-active {service}", check=False)
    return result.stdout.strip() == "active"


def _is_enabled(service: str) -> bool:
    result = SudoHelper.run(f"systemctl is-enabled {service}", check=False)
    return result.stdout.strip() == "enabled"


def disable_ssh() -> None:
    """Stop and disable sshd and related services."""

    # Check what's running
    active = [s for s in SERVICES if _is_active(s)]
    enabled = [s for s in SERVICES if _is_enabled(s)]
    targets = sorted(set(active + enabled))

    if not targets:
        print("No SSH-related services are currently active or enabled.")
        return

    print("The following services will be stopped and disabled:")
    for svc in targets:
        status = []
        if svc in active:
            status.append("running")
        if svc in enabled:
            status.append("enabled at boot")
        print(f"  - {svc} ({', '.join(status)})")

    print()
    answer = input("Continue? [y/N] ").strip().lower()
    if answer != "y":
        print("Aborted.")
        return

    print()
    for svc in targets:
        try:
            if svc in active:
                SudoHelper.run(f"systemctl stop {svc}")
                print(f"  Stopped: {svc}")
            if svc in enabled:
                SudoHelper.run(f"systemctl disable {svc}")
                print(f"  Disabled: {svc}")
        except Exception as e:
            print(f"  Failed ({svc}): {e}")

    print()
    print("Done. SSH and related services are disabled.")
    print("To re-enable, run: python -m safe_ssh_setup")
