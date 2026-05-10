"""User account creation and password authentication services."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.models.identity import User, UserPasswordCredential
from dionysus.security.passwords import hash_password, verify_password


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

    user = User(username=username, display_name=display_name)
    user.password_credential = UserPasswordCredential(password_hash=hash_password(password))
    session.add(user)
    session.flush()
    return user


def get_user_by_username(session: Session, username: str) -> User | None:
    """Return the user account for a username.

    Args:
        session: The database session used for lookup.
        username: The username to find.

    Returns:
        The matching user, or ``None`` when it does not exist.
    """

    return session.scalar(select(User).where(User.username == username))


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

    user = get_user_by_username(session, username)
    if user is None or not user.is_active or user.password_credential is None:
        return None
    if not verify_password(password, user.password_credential.password_hash):
        return None
    return user
