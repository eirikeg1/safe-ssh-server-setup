from jinja2 import Environment, PackageLoader

from safe_ssh_setup.models import Fail2BanConfig, PortKnockingConfig, SSHConfig


def _get_env():
    return Environment(
        loader=PackageLoader("safe_ssh_setup", "templates"),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_sshd(**overrides):
    params = dict(
        ssh=SSHConfig(),
        timestamp="test",
        sftp_server="/usr/libexec/openssh/sftp-server",
        sshd_config_dir="/etc/ssh/sshd_config.d",
    )
    params.update(overrides)
    return _get_env().get_template("sshd_config.j2").render(**params)


def render_jail(**overrides):
    params = dict(
        f2b=Fail2BanConfig(),
        ssh_port=2222,
        banaction="iptables-multiport",
        banaction_allports="iptables-allports",
        backend="auto",
        timestamp="test",
    )
    params.update(overrides)
    return _get_env().get_template("fail2ban_jail.j2").render(**params)


# --------------------------------------------------------------- sshd_config


def test_sshd_config_renders():
    result = render_sshd()
    assert "Port 22" in result
    assert "PermitRootLogin no" in result
    assert "PasswordAuthentication no" in result
    assert "PubkeyAuthentication yes" in result
    assert "X11Forwarding no" in result
    assert "chacha20-poly1305@openssh.com" in result
    assert "MaxAuthTries 3" in result


def test_sshd_config_custom_port():
    result = render_sshd(ssh=SSHConfig(port=2222, password_authentication=True))
    assert "Port 2222" in result
    assert "PasswordAuthentication yes" in result


def test_sftp_subsystem_path_is_supplied_per_system():
    """A hardcoded Debian path silently breaks sftp/scp on RHEL; sshd -t
    does not check that the Subsystem binary exists."""
    result = render_sshd(sftp_server="/usr/libexec/openssh/sftp-server")
    assert "Subsystem sftp /usr/libexec/openssh/sftp-server" in result

    debian = render_sshd(sftp_server="/usr/lib/openssh/sftp-server")
    assert "Subsystem sftp /usr/lib/openssh/sftp-server" in debian

    builtin = render_sshd(sftp_server="internal-sftp")
    assert "Subsystem sftp internal-sftp" in builtin


def test_sshd_config_has_no_deprecated_challenge_response_option():
    """It is a dead alias for KbdInteractiveAuthentication, which precedes it."""
    assert "ChallengeResponseAuthentication" not in render_sshd()


def test_sshd_config_sets_authorized_keys_file():
    assert "AuthorizedKeysFile .ssh/authorized_keys" in render_sshd()


def test_allow_users_is_emitted_when_set():
    result = render_sshd(ssh=SSHConfig(allow_users=["eirik", "alice@10.0.0.*"]))
    assert "AllowUsers eirik alice@10.0.0.*" in result


def test_allow_users_is_omitted_when_unrestricted():
    """No directive at all, rather than an empty one that would deny everyone."""
    assert "AllowUsers" not in render_sshd(ssh=SSHConfig(allow_users=[]))


def test_sshd_config_documents_that_dropins_are_ignored():
    result = render_sshd()
    assert "does not Include" in result


# ------------------------------------------------------------------ fail2ban


def test_fail2ban_jail_is_always_named_sshd():
    """Fail2Ban ships filter.d/sshd.conf only. A jail named after the systemd
    unit ("ssh" on Debian) references a filter that does not exist, and the
    service fails to start."""
    for backend in ("auto", "systemd"):
        result = render_jail(backend=backend)
        assert "[sshd]" in result
        assert "filter = sshd" in result
        assert "[ssh]\n" not in result
        assert "filter = ssh\n" not in result


def test_fail2ban_jail_renders_settings():
    result = render_jail()
    assert "port = 2222" in result
    assert "maxretry = 5" in result
    assert "findtime = 600" in result
    assert "bantime = 3600" in result


def test_fail2ban_ban_action_is_parameterised():
    firewalld = render_jail(
        banaction="firewallcmd-ipset", banaction_allports="firewallcmd-ipset"
    )
    assert "banaction = firewallcmd-ipset" in firewalld
    assert "iptables-multiport" not in firewalld


def test_fail2ban_omits_logpath_with_the_systemd_backend():
    """logpath is meaningless (and noisy) when reading from the journal."""
    systemd = render_jail(backend="systemd")
    assert "backend = systemd" in systemd
    assert "logpath" not in systemd

    file_based = render_jail(backend="auto")
    assert "logpath = %(sshd_log)s" in file_based


# ------------------------------------------------------------------- knockd


def test_knockd_renders_with_firewall_commands():
    knock = PortKnockingConfig(enabled=True, sequence=[7000, 8000, 9000])
    result = _get_env().get_template("knockd.j2").render(
        knock=knock,
        ssh_port=2222,
        firewall_name="ufw",
        open_command="ufw insert 1 allow from %IP% to any port 2222 proto tcp",
        close_command="ufw delete allow from %IP% to any port 2222 proto tcp",
        timestamp="test",
    )

    assert "7000,8000,9000" in result
    assert "9000,8000,7000" in result  # reverse sequence for close
    assert "ufw insert 1 allow" in result
    # A raw appended iptables rule sits behind ufw/firewalld and never matches.
    assert "iptables -A" not in result


def test_knockd_service_override_pins_the_interface():
    result = _get_env().get_template("knockd_service_override.j2").render(
        interface="enp3s0", timestamp="test"
    )
    assert "ExecStart=\n" in result  # reset before overriding
    assert "/usr/sbin/knockd -i enp3s0" in result


# ------------------------------------------------------------- auto updates


def test_dnf_automatic_renders():
    result = _get_env().get_template("dnf_automatic.j2").render(timestamp="test")
    assert "upgrade_type = security" in result
    assert "apply_updates = yes" in result


def test_unattended_upgrades_renders():
    result = _get_env().get_template("unattended_upgrades.j2").render(
        timestamp="test"
    )
    assert "Unattended-Upgrade::Allowed-Origins" in result
    assert 'Automatic-Reboot "false"' in result
    assert "-security" in result


def test_apt_periodic_config_actually_enables_upgrades():
    """Without APT::Periodic::Unattended-Upgrade, nothing ever runs."""
    result = _get_env().get_template("apt_auto_upgrades.j2").render(
        timestamp="test"
    )
    assert 'APT::Periodic::Unattended-Upgrade "1"' in result
    assert 'APT::Periodic::Update-Package-Lists "1"' in result
