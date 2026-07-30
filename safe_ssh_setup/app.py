from __future__ import annotations

from textual.app import App

from safe_ssh_setup.models import WizardState
from safe_ssh_setup.screens.apply import ApplyScreen
from safe_ssh_setup.screens.auto_updates import AutoUpdatesScreen
from safe_ssh_setup.screens.fail2ban import Fail2BanScreen
from safe_ssh_setup.screens.firewall import FirewallScreen
from safe_ssh_setup.screens.intrusion_detection import IntrusionDetectionScreen
from safe_ssh_setup.screens.port_knocking import PortKnockingScreen
from safe_ssh_setup.screens.review import ReviewScreen
from safe_ssh_setup.screens.ssh_hardening import SSHHardeningScreen
from safe_ssh_setup.screens.ssh_key import SSHKeyScreen
from safe_ssh_setup.screens.ssh_port import SSHPortScreen
from safe_ssh_setup.screens.summary import SummaryScreen
from safe_ssh_setup.screens.welcome import WelcomeScreen

# (screen class, long name, short label for the progress indicator).
# Port Knocking comes before Firewall because the firewall plan depends on
# whether knockd will be opening the SSH port.
WIZARD_STEPS = [
    (WelcomeScreen, "Welcome", "Welcome"),
    (SSHPortScreen, "SSH Port", "Port"),
    (SSHKeyScreen, "SSH Key", "Key"),
    (SSHHardeningScreen, "SSH Hardening", "Harden"),
    (Fail2BanScreen, "Fail2Ban", "Fail2Ban"),
    (PortKnockingScreen, "Port Knocking", "Knock"),
    (FirewallScreen, "Firewall", "Firewall"),
    (AutoUpdatesScreen, "Auto Updates", "Updates"),
    (IntrusionDetectionScreen, "Intrusion Detection", "IDS"),
    (ReviewScreen, "Review", "Review"),
    (ApplyScreen, "Apply", "Apply"),
    (SummaryScreen, "Summary", "Done"),
]


class SafeSSHSetupApp(App):
    TITLE = "safe-ssh-setup"
    SUB_TITLE = "SSH Server Hardening Wizard"
    CSS_PATH = "styles/app.tcss"
    BINDINGS = [
        ("q", "quit", "Quit"),
    ]

    def __init__(self, state: WizardState | None = None) -> None:
        super().__init__()
        self.wizard_state = state or WizardState()
        self.current_step = 0

    @property
    def step_labels(self) -> list[str]:
        return [short for _, _, short in WIZARD_STEPS]

    def on_mount(self) -> None:
        self.push_screen(self._make_screen(0))

    def _make_screen(self, index: int):
        screen_cls, _name, _short = WIZARD_STEPS[index]
        return screen_cls(
            state=self.wizard_state,
            step_index=index,
            total_steps=len(WIZARD_STEPS),
        )

    def action_next_step(self) -> None:
        if self.current_step < len(WIZARD_STEPS) - 1:
            self.current_step += 1
            # Screens are rebuilt from wizard_state, so a screen revisited
            # after going Back shows the values the user actually chose.
            self.push_screen(self._make_screen(self.current_step))

    def action_prev_step(self) -> None:
        if self.current_step > 0:
            self.current_step -= 1
            self.pop_screen()

    def action_finish(self) -> None:
        self.exit()
