"""Shared authentication cookie names and security helpers."""

from fastapi import Request

from dionysus.config import Environment

SESSION_COOKIE = "dionysus_session"
CSRF_COOKIE = "dionysus_login_csrf"


def cookies_secure(request: Request) -> bool:
    """Return whether authentication cookies should be marked Secure.

    Args:
        request: The incoming request carrying app settings and URL metadata.

    Returns:
        ``True`` when running in production or serving the current request over
        HTTPS, otherwise ``False``.
    """

    settings = request.app.state.settings
    return settings.environment == Environment.PRODUCTION or request.url.scheme == "https"
