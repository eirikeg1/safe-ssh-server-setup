from datetime import datetime

from jinja2 import Environment, PackageLoader

from safe_ssh_setup.models import Fail2BanConfig, PortKnockingConfig, SSHConfig


def _get_env():
    return Environment(
        loader=PackageLoader("safe_ssh_setup", "templates"),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def test_sshd_config_renders():
    env = _get_env()
    template = env.get_template("sshd_config.j2")
    result = template.render(ssh=SSHConfig(), timestamp="test")

    assert "Port 22" in result
    assert "PermitRootLogin no" in result
    assert "PasswordAuthentication no" in result
    assert "PubkeyAuthentication yes" in result
    assert "X11Forwarding no" in result
    assert "chacha20-poly1305@openssh.com" in result
    assert "MaxAuthTries 3" in result


def test_sshd_config_custom_port():
    env = _get_env()
    template = env.get_template("sshd_config.j2")
    cfg = SSHConfig(port=2222, password_authentication=True)
    result = template.render(ssh=cfg, timestamp="test")

    assert "Port 2222" in result
    assert "PasswordAuthentication yes" in result


def test_fail2ban_jail_renders():
    env = _get_env()
    template = env.get_template("fail2ban_jail.j2")
    result = template.render(
        f2b=Fail2BanConfig(),
        ssh_port=2222,
        ssh_service="sshd",
        timestamp="test",
    )

    assert "[sshd]" in result
    assert "port = 2222" in result
    assert "maxretry = 5" in result
    assert "filter = sshd" in result


def test_fail2ban_jail_debian_service():
    env = _get_env()
    template = env.get_template("fail2ban_jail.j2")
    result = template.render(
        f2b=Fail2BanConfig(),
        ssh_port=22,
        ssh_service="ssh",
        timestamp="test",
    )

    assert "[ssh]" in result
    assert "filter = ssh" in result


def test_knockd_renders():
    env = _get_env()
    template = env.get_template("knockd.j2")
    knock = PortKnockingConfig(enabled=True, sequence=[7000, 8000, 9000])
    result = template.render(knock=knock, ssh_port=2222, timestamp="test")

    assert "7000,8000,9000" in result
    assert "9000,8000,7000" in result  # reverse sequence for close
    assert "--dport 2222" in result


def test_dnf_automatic_renders():
    env = _get_env()
    template = env.get_template("dnf_automatic.j2")
    result = template.render(timestamp="test")

    assert "upgrade_type = security" in result
    assert "apply_updates = yes" in result


def test_unattended_upgrades_renders():
    env = _get_env()
    template = env.get_template("unattended_upgrades.j2")
    result = template.render(timestamp="test")

    assert "Unattended-Upgrade::Allowed-Origins" in result
    assert 'Automatic-Reboot "false"' in result
