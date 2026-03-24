from __future__ import annotations

from textual.app import App

from safe_ssh_setup.models import WizardState
from safe_ssh_setup.screens.welcome import WelcomeScreen
from safe_ssh_setup.screens.ssh_port import SSHPortScreen
from safe_ssh_setup.screens.ssh_key import SSHKeyScreen
from safe_ssh_setup.screens.ssh_hardening import SSHHardeningScreen
from safe_ssh_setup.screens.fail2ban import Fail2BanScreen
from safe_ssh_setup.screens.firewall import FirewallScreen
from safe_ssh_setup.screens.auto_updates import AutoUpdatesScreen
from safe_ssh_setup.screens.port_knocking import PortKnockingScreen
from safe_ssh_setup.screens.intrusion_detection import IntrusionDetectionScreen
from safe_ssh_setup.screens.review import ReviewScreen
from safe_ssh_setup.screens.apply import ApplyScreen
from safe_ssh_setup.screens.summary import SummaryScreen


WIZARD_STEPS = [
    (WelcomeScreen, "Welcome"),
    (SSHPortScreen, "SSH Port"),
    (SSHKeyScreen, "SSH Key"),
    (SSHHardeningScreen, "SSH Hardening"),
    (Fail2BanScreen, "Fail2Ban"),
    (FirewallScreen, "Firewall"),
    (AutoUpdatesScreen, "Auto Updates"),
    (PortKnockingScreen, "Port Knocking"),
    (IntrusionDetectionScreen, "Intrusion Detection"),
    (ReviewScreen, "Review"),
    (ApplyScreen, "Apply"),
    (SummaryScreen, "Summary"),
]


class SafeSSHSetupApp(App):
    TITLE = "safe-ssh-setup"
    SUB_TITLE = "SSH Server Hardening Wizard"
    CSS_PATH = "styles/app.tcss"
    BINDINGS = [
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.wizard_state = WizardState()
        self.current_step = 0

    def on_mount(self) -> None:
        self.push_screen(self._make_screen(0))

    def _make_screen(self, index: int):
        screen_cls, _label = WIZARD_STEPS[index]
        return screen_cls(
            state=self.wizard_state,
            step_index=index,
            total_steps=len(WIZARD_STEPS),
        )

    def action_next_step(self) -> None:
        if self.current_step < len(WIZARD_STEPS) - 1:
            self.current_step += 1
            self.push_screen(self._make_screen(self.current_step))

    def action_prev_step(self) -> None:
        if self.current_step > 0:
            self.current_step -= 1
            self.pop_screen()

    def action_finish(self) -> None:
        self.exit()
