"""Pure validation helpers.

Kept free of Textual imports so the rules can be unit-tested directly.
"""

from __future__ import annotations

import base64
import random
import re

KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)

# Anchored at both ends: an unanchored pattern lets arbitrary trailing text
# through, which then reaches a shell or corrupts authorized_keys.
PUBLIC_KEY_PATTERN = re.compile(
    r"^(?P<type>[A-Za-z0-9@.\-]+)"
    r"[ \t]+(?P<blob>[A-Za-z0-9+/]+={0,3})"
    r"(?:[ \t]+(?P<comment>[^\r\n]*))?$"
)

# Anything that would be special to a shell, or would split a key across lines.
UNSAFE_COMMENT_CHARS = set("\"'`$\\\n\r\t;&|<>()")

MIN_UNPRIVILEGED_PORT = 1024
MAX_PORT = 65535


class ValidationError(ValueError):
    pass


def validate_public_key(raw: str) -> str:
    """Validate an SSH public key and return its normalised single-line form.

    Raises :class:`ValidationError` with a user-facing message.
    """
    if raw is None:
        raise ValidationError("Please paste your public key.")

    text = raw.strip()
    if not text:
        raise ValidationError("Please paste your public key.")

    if "\n" in text or "\r" in text:
        raise ValidationError(
            "A public key must be a single line. Your paste contains a line "
            "break — copy the output of 'cat ~/.ssh/id_ed25519.pub' exactly."
        )

    match = PUBLIC_KEY_PATTERN.match(text)
    if not match:
        raise ValidationError(
            "That doesn't look like a valid public key. Expected: "
            "'<type> <base64> [comment]'."
        )

    key_type = match.group("type")
    if key_type not in KEY_TYPES:
        raise ValidationError(
            f"Unsupported key type '{key_type}'. Supported types: "
            + ", ".join(KEY_TYPES)
        )

    blob = match.group("blob")
    try:
        decoded = base64.b64decode(blob, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValidationError("The key's base64 data is malformed.") from exc

    # The blob is length-prefixed and starts with the key type it claims.
    if len(decoded) < 4:
        raise ValidationError("The key's base64 data is too short to be a key.")
    declared_len = int.from_bytes(decoded[:4], "big")
    if declared_len > len(decoded) - 4:
        raise ValidationError("The key's base64 data is truncated.")
    declared_type = decoded[4 : 4 + declared_len].decode("ascii", "replace")
    if declared_type != key_type:
        raise ValidationError(
            f"Key type mismatch: the key says '{key_type}' but its data "
            f"contains '{declared_type}'."
        )

    comment = match.group("comment") or ""
    bad = sorted(UNSAFE_COMMENT_CHARS & set(comment))
    if bad:
        raise ValidationError(
            "The key comment contains characters that are not allowed: "
            + " ".join(repr(c) for c in bad)
        )

    return f"{key_type} {blob}{(' ' + comment.strip()) if comment.strip() else ''}"


def is_valid_public_key(raw: str) -> bool:
    try:
        validate_public_key(raw)
    except ValidationError:
        return False
    return True


def authorized_keys_has_key(content: str) -> bool:
    """True when the file holds at least one syntactically valid key."""
    for line in (content or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # authorized_keys lines may carry leading options; try the whole line
        # first, then the last two/three fields.
        if is_valid_public_key(stripped):
            return True
        parts = stripped.split()
        for start in range(1, len(parts)):
            if is_valid_public_key(" ".join(parts[start:])):
                return True
    return False


def parse_port(raw: str | None) -> int:
    if raw is None or not str(raw).strip():
        raise ValidationError("Please enter a port number.")
    try:
        return int(str(raw).strip())
    except ValueError:
        raise ValidationError("Port must be a whole number.") from None


def validate_port(port: int, *, allow_privileged_22: bool = True) -> None:
    if not 1 <= port <= MAX_PORT:
        raise ValidationError(f"Port must be between 1 and {MAX_PORT}.")
    if port < MIN_UNPRIVILEGED_PORT and not (allow_privileged_22 and port == 22):
        raise ValidationError(
            f"Port {port} is a privileged port. Use a port >= "
            f"{MIN_UNPRIVILEGED_PORT} or keep 22."
        )


def pick_random_port(
    ephemeral_floor: int,
    in_use: set[int] | None = None,
    rng: random.Random | None = None,
) -> int:
    """Choose a high port that will not collide with the ephemeral range.

    Ports at or above the ephemeral floor get handed out to outbound
    connections, so sshd can intermittently fail to bind at boot.
    """
    rng = rng or random.Random()
    in_use = in_use or set()

    upper = min(ephemeral_floor - 1, MAX_PORT)
    lower = MIN_UNPRIVILEGED_PORT
    if upper <= lower:
        lower, upper = MIN_UNPRIVILEGED_PORT, MIN_UNPRIVILEGED_PORT + 1000

    for _ in range(200):
        candidate = rng.randint(lower, upper)
        if candidate not in in_use:
            return candidate

    for candidate in range(lower, upper + 1):
        if candidate not in in_use:
            return candidate
    return lower


def parse_knock_sequence(raw: str) -> list[int]:
    if not raw or not raw.strip():
        raise ValidationError("Knock sequence must not be empty.")
    try:
        ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
    except ValueError:
        raise ValidationError(
            "Knock sequence must be comma-separated port numbers."
        ) from None
    if len(ports) < 3:
        raise ValidationError(
            "Knock sequence needs at least 3 ports to be meaningful."
        )
    for port in ports:
        if not 1 <= port <= MAX_PORT:
            raise ValidationError(f"Invalid port in knock sequence: {port}")
    if len(set(ports)) != len(ports):
        raise ValidationError("Knock sequence must not repeat a port.")
    return ports


def validate_positive(raw: str | None, name: str, minimum: int = 1) -> int:
    try:
        value = int(str(raw).strip()) if str(raw).strip() else 0
    except (ValueError, AttributeError):
        raise ValidationError(f"{name} must be a whole number.") from None
    if value < minimum:
        raise ValidationError(f"{name} must be at least {minimum}.")
    return value


def validate_non_negative(raw: str | None, name: str) -> int:
    try:
        value = int(str(raw).strip()) if str(raw).strip() else 0
    except (ValueError, AttributeError):
        raise ValidationError(f"{name} must be a whole number.") from None
    if value < 0:
        raise ValidationError(f"{name} cannot be negative.")
    return value


# sshd's AllowUsers accepts "user" and "user@host-pattern" entries. Anything
# outside this set could inject a second directive into sshd_config.
ALLOW_USER_PATTERN = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,31}\$?"
    r"(?:@[A-Za-z0-9_.\-*?\[\]:/]+)?$"
)


def parse_user_list(raw: str) -> list[str]:
    """Split an AllowUsers list on commas or whitespace and validate each entry.

    A typo here locks you out, so the rules are strict and the errors name the
    offending entry.
    """
    if raw and ("\n" in raw or "\r" in raw):
        # Splitting would silently turn a pasted block into a list of
        # "usernames". Refuse it so the mistake is visible.
        raise ValidationError(
            "The allowed users list must be a single line of names separated "
            "by spaces or commas."
        )

    entries = [e for e in re.split(r"[,\s]+", (raw or "").strip()) if e]
    if not entries:
        raise ValidationError(
            "Enter at least one username, or turn off login restriction."
        )

    seen: list[str] = []
    for entry in entries:
        if not ALLOW_USER_PATTERN.match(entry):
            raise ValidationError(
                f"{entry!r} is not a valid username. Use names like 'eirik' "
                "or patterns like 'eirik@192.168.1.*'."
            )
        if entry not in seen:
            seen.append(entry)
    return seen


def user_in_allow_list(user: str, allow_users: list[str]) -> bool:
    """Whether `user` can log in given an AllowUsers list.

    Entries may carry a host pattern, so compare only the account part.
    """
    if not allow_users:
        return True
    return any(entry.split("@", 1)[0] == user for entry in allow_users)


def validate_algorithm_list(raw: str, name: str) -> list[str]:
    """Split a comma-separated crypto list, rejecting shell/config metacharacters."""
    items = [item.strip() for item in (raw or "").split(",") if item.strip()]
    if not items:
        raise ValidationError(f"{name} must not be empty.")
    for item in items:
        if not re.fullmatch(r"[A-Za-z0-9@._+\-]+", item):
            raise ValidationError(f"Invalid entry in {name}: {item!r}")
    return items
