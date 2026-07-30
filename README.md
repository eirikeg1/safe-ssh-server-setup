# safe-ssh-setup

A terminal TUI wizard that guides you through setting up a SSH server with security measures. Can be used to easily set up SSH safely on your home network.

## Features

- SSH daemon hardening (key-only auth, strong ciphers, disable root)
- Ed25519 SSH key setup (paste from your client, or generate on the server)
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

Run it as **the user you want to log in as** — not as root. It prompts for sudo
once and only escalates when applying system changes. Running directly as root
is refused, because your key would be installed for the root account while root
login is being disabled.

### Disable SSH

```bash
python -m safe_ssh_setup --disable
```

Stops and disables sshd and related services (fail2ban, knockd). Prompts for confirmation before making changes, and warns if you are connected over SSH.

### Rollback

Every run creates a timestamped backup in `/var/backups/safe-ssh-setup/`. The
rollback script is written **before** any change is made, so an interrupted run
is still recoverable.

```bash
# Using the generated rollback script
sudo bash /var/backups/safe-ssh-setup/YYYYMMDD-HHMMSS/rollback.sh

# Or using the Python module
python -m safe_ssh_setup.rollback /var/backups/safe-ssh-setup/YYYYMMDD-HHMMSS/

# List available backups
python -m safe_ssh_setup.rollback
```

Rollback restores every file the run modified and deletes every file it created.
Firewall rules, enabled services, SELinux port labels and installed packages are
**not** reverted automatically; the script prints what to undo by hand.

## Wizard Steps

| Step | What it configures | Skippable |
|------|--------------------|-----------|
| Welcome | Detects your distro and checks prerequisites | No |
| SSH Port | Choose a port (random high port, custom, or keep 22) | Yes |
| SSH Key | Paste your client's public key, or generate a keypair | Yes |
| SSH Hardening | sshd_config — auth, ciphers, forwarding, timeouts | Yes |
| Fail2Ban | Brute-force protection (ban time, max retries) | Yes |
| Port Knocking | Hide SSH port behind a knock sequence | Yes |
| Firewall | Allow SSH port only, rate limiting, default deny | Yes |
| Auto Updates | unattended-upgrades (Debian) or dnf-automatic (Fedora) | Yes |
| Intrusion Detection | rkhunter rootkit scanner with a daily scan | Yes |
| Review | Dry-run — see diffs of all planned changes | No |
| Apply | Execute changes with progress bar and backup | No |
| Summary | Connection command, backup location, rollback info | No |

Port Knocking comes before Firewall because the firewall plan depends on whether
knockd will be opening the SSH port.

## How it avoids locking you out

- **Nothing runs until you approve the Review step**, which lists every action in
  the exact order it will execute.
- **The Review step refuses to continue** if the configuration would lock you
  out: key-only authentication with no installed key, a moved port behind an
  active firewall that nothing will open, or port knocking without an
  acknowledged risk.
- **sshd is configured, restarted and verified before the firewall is touched.**
  If the config fails validation, the daemon fails to restart, or nothing ends up
  listening on the new port, the run aborts, the original `sshd_config` is
  restored and restarted, and the firewall is left alone.
- **Non-standard ports are labelled for SELinux** (`semanage port -a -t
  ssh_port_t`) on the RHEL family, so sshd can actually bind them.
- **Failures are reported as failures.** The summary lists any action that did
  not succeed instead of claiming success.
- **The rollback script exists before the first change**, so an interrupted run
  is still recoverable.

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
- Jail and filter are named `sshd` on every distro, with the ban action matched
  to the firewall in use (`firewallcmd-ipset` on firewalld, `iptables-multiport`
  on ufw)

**Firewall**
- Default deny incoming
- SSH port only, with rate limiting on ufw

Rate limiting is offered on ufw only. firewalld's rich-rule `limit` applies to
the rule as a whole rather than per source address, so a single attacker could
exhaust it and lock you out; Fail2Ban provides brute-force protection there.

## Notes

The generated `sshd_config` deliberately does not `Include
/etc/ssh/sshd_config.d/*.conf`. The wizard owns the whole configuration so that
what you reviewed is exactly what runs — distro and cloud-init drop-ins are
ignored.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
