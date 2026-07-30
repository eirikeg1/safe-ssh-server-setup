"""Disable SSH and related services."""

from __future__ import annotations

from safe_ssh_setup.sudo import SudoHelper
from safe_ssh_setup.system import is_ssh_session

# Debian names the unit "ssh", Fedora "sshd"; on Debian one is an alias of the
# other, so acting on both is harmless.
SERVICES = ["ssh", "sshd", "fail2ban", "knockd"]


def _is_active(service: str) -> bool:
    result = SudoHelper.run(["systemctl", "is-active", service])
    return result.stdout.strip() == "active"


def _is_enabled(service: str) -> bool:
    result = SudoHelper.run(["systemctl", "is-enabled", service])
    # "alias" means the unit is another unit's alias (Debian's sshd -> ssh);
    # "enabled-runtime" is enabled until reboot.
    return result.stdout.strip() in ("enabled", "enabled-runtime")


def disable_ssh() -> None:
    """Stop and disable sshd and related services."""
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

    if is_ssh_session():
        print(
            "\nWARNING: you are connected over SSH. Your current session will\n"
            "survive, but you will not be able to reconnect until SSH is\n"
            "re-enabled. Make sure you have console or physical access."
        )

    print()
    answer = input("Continue? [y/N] ").strip().lower()
    if answer != "y":
        print("Aborted.")
        return

    print()
    for svc in targets:
        if svc in active:
            result = SudoHelper.run(["systemctl", "stop", svc])
            if result.returncode == 0:
                print(f"  Stopped: {svc}")
            else:
                print(f"  Failed to stop {svc}: {result.stderr.strip()}")
        if svc in enabled:
            result = SudoHelper.run(["systemctl", "disable", svc])
            if result.returncode == 0:
                print(f"  Disabled: {svc}")
            else:
                print(f"  Failed to disable {svc}: {result.stderr.strip()}")

    print()
    print("Done. SSH and related services are disabled.")
    print("To re-enable, run: python -m safe_ssh_setup")
