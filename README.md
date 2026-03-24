# safe-ssh-setup

A terminal TUI wizard that hardens your SSH server step by step. Designed to make it safe to expose SSH on your home network.

## Features

- SSH daemon hardening (key-only auth, strong ciphers, disable root)
- Ed25519 SSH key generation and setup
- Fail2Ban brute-force protection
- Firewall configuration (UFW or firewalld)
- Automatic security updates
- Port knocking (optional)
- Intrusion detection with rkhunter (optional)
- Dry-run review of all changes before applying
- Automatic backup and one-command rollback

## Supported Distributions

| Family | Distros | Package Manager | Firewall |
|--------|---------|-----------------|----------|
| Debian | Debian, Ubuntu | apt | UFW |
| RHEL | Fedora, RHEL, CentOS, Rocky, Alma | dnf | firewalld |

## Installation

```bash
git clone https://github.com/eirikeg1/safe-ssh-server-setup.git
cd safe-ssh-server-setup
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python 3.10+ and Linux.

## Usage

### Run the wizard

```bash
python -m safe_ssh_setup
```

The tool will prompt for sudo credentials before launching the TUI. It runs as your normal user and only escalates to sudo when applying system changes.

### Disable SSH

```bash
python -m safe_ssh_setup --disable
```

Stops and disables sshd and related services (fail2ban, knockd). Prompts for confirmation before making changes.

### Rollback

Every run creates a timestamped backup in `/var/backups/safe-ssh-setup/`. To restore:

```bash
# Using the generated rollback script
sudo bash /var/backups/safe-ssh-setup/YYYYMMDD-HHMMSS/rollback.sh

# Or using the Python module
python -m safe_ssh_setup.rollback /var/backups/safe-ssh-setup/YYYYMMDD-HHMMSS/

# List available backups
python -m safe_ssh_setup.rollback
```

## Wizard Steps

| Step | What it configures | Skippable |
|------|--------------------|-----------|
| Welcome | Detects your distro and checks prerequisites | No |
| SSH Port | Choose a port (random high port, custom, or keep 22) | Yes |
| SSH Key | Generate an Ed25519 keypair, set up authorized_keys | Yes |
| SSH Hardening | sshd_config — auth, ciphers, forwarding, timeouts | Yes |
| Fail2Ban | Brute-force protection (ban time, max retries) | Yes |
| Firewall | Allow SSH port only, rate limiting, default deny | Yes |
| Auto Updates | unattended-upgrades (Debian) or dnf-automatic (Fedora) | Yes |
| Port Knocking | Hide SSH port behind a knock sequence | Yes |
| Intrusion Detection | rkhunter rootkit scanner with daily cron | Yes |
| Review | Dry-run — see diffs of all planned changes | No |
| Apply | Execute changes with progress bar and backup | No |
| Summary | Connection command, backup location, rollback info | No |

## Default Security Settings

The wizard applies these defaults (all configurable in the TUI):

**Authentication**
- Key-only authentication (passwords disabled)
- Root login disabled
- Max 3 authentication attempts
- 30s login grace time
- 5 minute idle timeout

**Cryptography**
- Ciphers: `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`
- MACs: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`
- Key exchange: `sntrup761x25519-sha512` (post-quantum), `curve25519-sha256`

**Forwarding**
- X11, agent, and TCP forwarding all disabled

**Fail2Ban**
- Ban after 5 failed attempts within 10 minutes
- 1 hour ban duration

**Firewall**
- Default deny incoming
- SSH port only, with rate limiting

## License

MIT
