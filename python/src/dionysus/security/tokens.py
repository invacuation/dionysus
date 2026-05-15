"""Secure token generation and digest helpers."""

from hashlib import sha256
from secrets import token_urlsafe


def generate_token() -> str:
    """Return a URL-safe random bearer token.

    Returns:
        A raw bearer token for session or API authentication. Callers should
        return it to the client once and store only a digest.
    """

    return token_urlsafe(32)


def token_digest(token: str) -> str:
    """Return the SHA-256 hex digest for a token.

    Args:
        token: The raw bearer token to digest.

    Returns:
        A hex digest that can be stored without persisting the raw secret.
    """

    return sha256(token.encode("utf-8")).hexdigest()
