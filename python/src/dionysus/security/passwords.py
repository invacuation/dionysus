"""Password hashing and verification helpers backed by Argon2."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Return an Argon2 hash for a plaintext password.

    Args:
        password: The raw password supplied by the user.

    Returns:
        An Argon2 password hash suitable for storage. The raw password is not
        stored by this helper.
    """

    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether a plaintext password matches a stored hash.

    Malformed hashes and verification errors fail closed and return ``False``.

    Args:
        password: The raw password supplied for authentication.
        password_hash: The stored Argon2 password hash.

    Returns:
        ``True`` when the password matches; otherwise ``False``.
    """

    try:
        return _password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False
