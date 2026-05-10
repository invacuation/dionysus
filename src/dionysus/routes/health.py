"""Health check routes."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Return a simple liveness response for health checks.

    Returns:
        A status payload indicating that the application process is alive.
    """

    return {"status": "ok"}
