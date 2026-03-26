from unittest.mock import patch

import pytest

from safe_ssh_setup.distro import (
    DistroDetectionError,
    DistroInfo,
    FirewallAdapter,
    PackageManager,
    detect_distro,
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


def test_package_manager_apt():
    info = _mock_detect(UBUNTU_OS_RELEASE)
    pm = PackageManager(info)
    assert "apt-get install -y fail2ban" in pm.install_command(["fail2ban"])
    assert "apt-get update" in pm.update_command()


def test_package_manager_dnf():
    info = _mock_detect(FEDORA_OS_RELEASE)
    pm = PackageManager(info)
    assert "dnf install -y fail2ban" in pm.install_command(["fail2ban"])
    assert "dnf check-update" in pm.update_command()


def test_firewall_adapter_ufw():
    info = _mock_detect(UBUNTU_OS_RELEASE)
    fw = FirewallAdapter(info)
    assert fw.install_packages() == ["ufw"]
    cmds = fw.allow_port_commands(2222)
    assert any("ufw allow 2222/tcp" in c for c in cmds)


def test_firewall_adapter_firewalld():
    info = _mock_detect(FEDORA_OS_RELEASE)
    fw = FirewallAdapter(info)
    assert fw.install_packages() == ["firewalld"]
    cmds = fw.allow_port_commands(2222)
    assert any("2222/tcp" in c for c in cmds)
