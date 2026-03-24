from __future__ import annotations

import os
import sys


def _ensure_linux() -> None:
    if sys.platform != "linux":
        print("Error: safe-ssh-setup only supports Linux.")
        sys.exit(1)


def _ensure_sudo() -> None:
    if os.geteuid() == 0:
        print(
            "Warning: Running as root is not recommended.\n"
            "The tool will use sudo only when needed.\n"
        )

    from safe_ssh_setup.sudo import SudoHelper

    if not SudoHelper.check_sudo_available():
        print("This tool requires sudo access to configure system services.")
        print("Please enter your password when prompted:\n")
        if not SudoHelper.prompt_sudo():
            print("\nError: Could not obtain sudo credentials.")
            sys.exit(1)
        print()


def main() -> None:
    _ensure_linux()
    _ensure_sudo()

    if "--disable" in sys.argv:
        from safe_ssh_setup.disable import disable_ssh
        disable_ssh()
        return

    from safe_ssh_setup.app import SafeSSHSetupApp

    app = SafeSSHSetupApp()
    app.run()


if __name__ == "__main__":
    main()
