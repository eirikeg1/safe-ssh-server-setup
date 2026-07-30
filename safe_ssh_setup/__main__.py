from __future__ import annotations

import argparse
import sys

from safe_ssh_setup import __version__


def _ensure_linux() -> None:
    if sys.platform != "linux":
        print("Error: safe-ssh-setup only supports Linux.")
        sys.exit(1)


def _ensure_user() -> None:
    """Refuse to run as bare root.

    Under plain root, ~/.ssh resolves to /root/.ssh, so the wizard would
    install your key for the root account while simultaneously setting
    PermitRootLogin no — a key you can never use.
    """
    from safe_ssh_setup.system import running_as_root_without_sudo_user

    if running_as_root_without_sudo_user():
        print(
            "Error: do not run safe-ssh-setup directly as root.\n"
            "\n"
            "It would install SSH keys for the root account while disabling\n"
            "root login, leaving you unable to log in.\n"
            "\n"
            "Run it as the user you want to log in as; it will ask for sudo\n"
            "when it needs to change system files:\n"
            "    python -m safe_ssh_setup"
        )
        sys.exit(1)


def _ensure_sudo() -> None:
    from safe_ssh_setup.sudo import SudoHelper

    if not SudoHelper.check_sudo_available():
        print("This tool requires sudo access to configure system services.")
        print("Please enter your password when prompted:\n")
        if not SudoHelper.prompt_sudo():
            print("\nError: Could not obtain sudo credentials.")
            sys.exit(1)
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safe-ssh-setup",
        description="TUI wizard for hardening SSH servers.",
    )
    parser.add_argument(
        "--disable",
        action="store_true",
        help="stop and disable sshd and related services, then exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"safe-ssh-setup {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    _ensure_linux()
    _ensure_user()
    _ensure_sudo()

    from safe_ssh_setup.sudo import SudoHelper

    keepalive = SudoHelper.start_keepalive()
    try:
        if args.disable:
            from safe_ssh_setup.disable import disable_ssh

            disable_ssh()
            return

        from safe_ssh_setup.app import SafeSSHSetupApp

        SafeSSHSetupApp().run()
    finally:
        keepalive.set()


if __name__ == "__main__":
    main()
