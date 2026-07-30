from unittest.mock import patch

import pytest

from safe_ssh_setup.distro import (
    DistroDetectionError,
    DistroInfo,
    FirewallAdapter,
    PackageManager,
    detect_distro,
    selinux_port_fallback,
    selinux_port_steps,
)
from safe_ssh_setup.models import DistroFamily

UBUNTU_OS_RELEASE = """\
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"""

FEDORA_OS_RELEASE = """\
NAME="Fedora Linux"
VERSION_ID="43"
ID=fedora
"""

ARCH_OS_RELEASE = """\
NAME="Arch Linux"
ID=arch
"""


def _mock_detect(content: str) -> DistroInfo:
    with patch("safe_ssh_setup.distro.Path") as mock_path:
        instance = mock_path.return_value
        instance.exists.return_value = True
        instance.read_text.return_value = content
        return detect_distro()


def test_detect_ubuntu():
    info = _mock_detect(UBUNTU_OS_RELEASE)
    assert info.family == DistroFamily.DEBIAN
    assert info.package_manager == "apt"
    assert info.firewall == "ufw"
    assert info.ssh_service == "ssh"
    assert info.auto_updates_package == "unattended-upgrades"


def test_detect_fedora():
    info = _mock_detect(FEDORA_OS_RELEASE)
    assert info.family == DistroFamily.RHEL
    assert info.package_manager == "dnf"
    assert info.firewall == "firewalld"
    assert info.ssh_service == "sshd"
    assert info.auto_updates_package == "dnf-automatic"


def test_detect_unsupported():
    with pytest.raises(DistroDetectionError, match="Unsupported"):
        _mock_detect(ARCH_OS_RELEASE)


def test_fedora_uses_a_timer_that_exists_on_dnf5():
    """dnf-automatic-install.timer was removed in dnf5 (Fedora 41+)."""
    info = _mock_detect(FEDORA_OS_RELEASE)
    assert info.auto_updates_timer == "dnf-automatic.timer"
    assert "install" not in info.auto_updates_timer


def test_fedora_ban_action_matches_firewalld():
    """Forcing iptables on an nftables/firewalld system breaks banning."""
    info = _mock_detect(FEDORA_OS_RELEASE)
    assert info.fail2ban_banaction == "firewallcmd-ipset"
    assert info.fail2ban_backend == "systemd"


def test_debian_ban_action_matches_iptables():
    info = _mock_detect(UBUNTU_OS_RELEASE)
    assert info.fail2ban_banaction == "iptables-multiport"


# ------------------------------------------------------------ package names


def test_package_manager_apt_builds_argv(debian):
    pm = PackageManager(debian)
    assert pm.install_command(["fail2ban"]) == [
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "fail2ban",
    ]
    assert pm.update_command() == ["apt-get", "update", "-y"]


def test_package_manager_dnf_builds_argv(fedora):
    pm = PackageManager(fedora)
    assert pm.install_command(["fail2ban"]) == ["dnf", "install", "-y", "fail2ban"]
    assert pm.update_command() == ["dnf", "check-update"]
    assert 100 in pm.update_ok_returncodes()


def test_knockd_package_name_differs_per_distro(debian, fedora):
    """Fedora has no "knockd" package; knockd ships inside knock-server."""
    assert PackageManager(debian).resolve("knockd") == "knockd"
    assert PackageManager(fedora).resolve("knockd") == "knock-server"
    assert PackageManager(fedora).install_command(["knockd"]) == [
        "dnf", "install", "-y", "knock-server",
    ]


def test_selinux_tools_package_name(fedora):
    assert PackageManager(fedora).resolve("selinux-tools") == (
        "policycoreutils-python-utils"
    )


# ---------------------------------------------------------------- firewalls


def test_ufw_opens_port_before_default_deny(debian):
    plan = FirewallAdapter(debian).plan(port=2222, rate_limiting=True)
    descriptions = [" ".join(step.argv) for step in plan]

    allow_index = next(i for i, d in enumerate(descriptions) if "limit" in d)
    deny_index = next(i for i, d in enumerate(descriptions) if "deny incoming" in d)
    enable_index = next(i for i, d in enumerate(descriptions) if "enable" in d)

    assert allow_index < deny_index < enable_index


def test_ufw_removes_stale_ssh_rules_only_off_port_22(debian):
    moved = FirewallAdapter(debian).plan(port=2222)
    assert any("OpenSSH" in " ".join(s.argv) for s in moved)

    kept = FirewallAdapter(debian).plan(port=22)
    assert not any("OpenSSH" in " ".join(s.argv) for s in kept)


def test_ufw_delete_rules_are_best_effort(debian):
    plan = FirewallAdapter(debian).plan(port=2222)
    deletes = [s for s in plan if "delete" in s.argv]
    assert deletes
    assert all(s.ignore_failure for s in deletes)


def test_firewalld_starts_the_daemon_before_using_firewall_cmd(fedora):
    """firewall-cmd talks to the daemon; it fails if firewalld is not running."""
    plan = FirewallAdapter(fedora).plan(port=2222)
    first = plan[0]
    assert first.argv == ["systemctl", "enable", "--now", "firewalld"]
    assert all(
        plan.index(step) > 0
        for step in plan
        if step.argv[0] == "firewall-cmd"
    )


def test_firewalld_reloads_once_at_the_end(fedora):
    plan = FirewallAdapter(fedora).plan(port=2222)
    reloads = [i for i, s in enumerate(plan) if s.argv == ["firewall-cmd", "--reload"]]
    assert len(reloads) == 1
    assert reloads[0] == len(plan) - 1


def test_firewalld_sets_zone_target_rather_than_switching_default_zone(fedora):
    """Switching the default zone drops the session and misses bound interfaces."""
    plan = FirewallAdapter(fedora).plan(port=2222, default_deny=True)
    argvs = [" ".join(s.argv) for s in plan]
    assert any("--set-target=DROP" in a for a in argvs)
    assert not any("--set-default-zone" in a for a in argvs)


def test_firewalld_binds_the_default_route_interface(fedora, monkeypatch):
    monkeypatch.setattr(
        "safe_ssh_setup.distro.default_interface", lambda: "enp3s0"
    )
    plan = FirewallAdapter(fedora).plan(port=2222)
    assert any("--change-interface=enp3s0" in " ".join(s.argv) for s in plan)


def test_rate_limiting_is_offered_only_where_it_is_per_source(debian, fedora):
    """firewalld's rich-rule limit is global and can be used to lock you out."""
    assert FirewallAdapter(debian).supports_rate_limiting is True
    assert FirewallAdapter(fedora).supports_rate_limiting is False

    plan = FirewallAdapter(fedora).plan(port=2222, rate_limiting=True)
    assert not any("limit" in " ".join(s.argv) for s in plan)


def test_port_knocking_can_leave_the_port_closed(debian):
    plan = FirewallAdapter(debian).plan(port=2222, open_ssh_port=False)
    assert not any(
        s.argv[:2] in (["ufw", "allow"], ["ufw", "limit"]) for s in plan
    )


def test_knock_commands_use_the_firewall_not_raw_iptables(debian, fedora):
    """An appended iptables rule is never reached behind ufw or firewalld."""
    ufw = FirewallAdapter(debian)
    assert "ufw insert 1 allow" in ufw.knock_open_command(2222)
    assert "iptables" not in ufw.knock_open_command(2222)

    fwd = FirewallAdapter(fedora)
    assert "firewall-cmd" in fwd.knock_open_command(2222)
    assert "--remove-rich-rule" in fwd.knock_close_command(2222)
    assert "iptables" not in fwd.knock_open_command(2222)


# ------------------------------------------------------------------ SELinux


def test_selinux_labels_non_default_ports():
    steps = selinux_port_steps(2222)
    assert steps
    assert steps[0].argv == [
        "semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", "2222",
    ]
    assert selinux_port_fallback(2222)[2] == "-m"


def test_selinux_labelling_skipped_for_port_22():
    assert selinux_port_steps(22) == []
