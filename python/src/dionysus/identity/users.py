"""User account creation and password authentication services."""

import unicodedata
from string import ascii_letters, digits

from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.models.identity import User, UserPasswordCredential
from dionysus.security.passwords import hash_password, verify_password

_USERNAME_CHARS = frozenset(ascii_letters + digits + ".!#$%&'*+/=?^_`{|}~-")
_DOMAIN_CHARS = frozenset(ascii_letters + digits + ".-")
_DOMAIN_LABEL_CHARS = frozenset(ascii_letters.lower() + digits + "-")


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(char).startswith("C") for char in value)


def _validate_unicode_domain_label(label: str) -> None:
    if (
        not label
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (char.isalnum() or char == "-") for char in label)
    ):
        raise ValueError("Invalid username")


def _validate_ascii_domain(ascii_domain: str) -> None:
    if len(ascii_domain) > 253:
        raise ValueError("Invalid username")

    for label in ascii_domain.split("."):
        if (
            not 1 <= len(label) <= 63
            or label[0] not in ascii_letters.lower() + digits
            or label[-1] not in ascii_letters.lower() + digits
            or any(char not in _DOMAIN_LABEL_CHARS for char in label)
        ):
            raise ValueError("Invalid username")


def canonicalize_username(username: str) -> str:
    """Return the stored username form for a login identifier."""

    trimmed = unicodedata.normalize("NFKC", username).strip()
    if any(char.isspace() for char in trimmed) or _has_control_character(trimmed):
        raise ValueError("Invalid username")

    at_count = trimmed.count("@")
    if at_count > 1:
        raise ValueError("Invalid username")

    if at_count == 0:
        canonical = trimmed
        if any(char not in _USERNAME_CHARS for char in canonical):
            raise ValueError("Invalid username")
    else:
        local, domain = trimmed.split("@")
        if not local or not domain:
            raise ValueError("Invalid username")
        if any(char not in _USERNAME_CHARS for char in local):
            raise ValueError("Invalid username")
        for label in domain.split("."):
            _validate_unicode_domain_label(label)

        try:
            ascii_domain = domain.lower().encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid username") from exc
        if any(char not in _DOMAIN_CHARS for char in ascii_domain):
            raise ValueError("Invalid username")
        _validate_ascii_domain(ascii_domain)
        canonical = f"{local}@{ascii_domain}"

    if not 3 <= len(canonical) <= 150:
        raise ValueError("Invalid username")
    return canonical


def validate_display_name(display_name: str) -> str:
    """Return the normalized display name."""

    normalized = unicodedata.normalize("NFKC", display_name).strip()
    if not 1 <= len(normalized) <= 200:
        raise ValueError("Invalid display name")
    return normalized


def validate_password(password: str) -> str:
    """Return a password that satisfies the account password policy."""

    if not 15 <= len(password) <= 256 or not password.strip():
        raise ValueError("Invalid password")
    return password


def create_user(session: Session, *, username: str, display_name: str, password: str) -> User:
    """Create a user with a hashed password credential.

    Args:
        session: The database session used to persist the user.
        username: The unique username for authentication.
        display_name: The human-readable name shown for the user.
        password: The raw password to hash before storage.

    Returns:
        The flushed user model with its password credential attached. The raw
        password is not stored.
    """

    user = User(
        username=canonicalize_username(username),
        display_name=validate_display_name(display_name),
    )
    user.password_credential = UserPasswordCredential(
        password_hash=hash_password(validate_password(password))
    )
    session.add(user)
    session.flush()
    return user


def set_user_password(session: Session, user: User, password: str) -> None:
    """Replace a user's local password credential with a new hashed password."""

    password_hash = hash_password(validate_password(password))
    if user.password_credential is None:
        user.password_credential = UserPasswordCredential(password_hash=password_hash)
    else:
        user.password_credential.password_hash = password_hash
    session.flush()


def get_user_by_username(session: Session, username: str) -> User | None:
    """Return the user account for a username.

    Args:
        session: The database session used for lookup.
        username: The username to find.

    Returns:
        The matching user, or ``None`` when it does not exist.
    """

    return session.scalar(select(User).where(User.username == canonicalize_username(username)))


def authenticate_user(session: Session, username: str, password: str) -> User | None:
    """Return an active user when the supplied password matches.

    Inactive users, missing credentials, mismatched passwords, and malformed
    stored hashes fail closed by returning ``None``.

    Args:
        session: The database session used for lookup.
        username: The username to authenticate.
        password: The raw password supplied by the user.

    Returns:
        The authenticated active user, or ``None`` when authentication fails.
    """

    try:
        user = get_user_by_username(session, username)
    except ValueError:
        return None
    if user is None or not user.is_active or user.password_credential is None:
        return None
    if not verify_password(password, user.password_credential.password_hash):
        return None
    return user
