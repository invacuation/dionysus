"""React frontend static serving helpers."""

from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

router = APIRouter()
fallback_router = APIRouter()
FRONTEND_ROUTE_PREFIXES = {"admin", "findings", "imports", "inventory"}


def default_frontend_dist() -> Path:
    """Return the default built frontend distribution directory.

    Returns:
        Path to the repository-level ``frontend/dist`` directory.
    """

    return Path(__file__).resolve().parents[3] / "frontend" / "dist"


def mount_frontend_assets(app: FastAPI, frontend_dist: Path) -> None:
    """Mount built frontend assets when they exist.

    Args:
        app: FastAPI application object.
        frontend_dist: Built Vite distribution directory.

    Returns:
        None.
    """

    assets_dir = frontend_dist / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")


def _react_index(request: Request) -> FileResponse:
    frontend_dist = getattr(request.app.state, "frontend_dist", default_frontend_dist())
    index_path = Path(frontend_dist) / "index.html"
    if not index_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="React frontend build not found. Run `cd frontend && bun run build`.",
        )
    return FileResponse(index_path)


@router.get("/", include_in_schema=False)
def react_app_root(request: Request) -> FileResponse:
    """Return the React app entrypoint for the root route."""

    return _react_index(request)


@router.get("/findings", include_in_schema=False)
@router.get("/imports", include_in_schema=False)
@router.get("/inventory", include_in_schema=False)
@router.get("/admin", include_in_schema=False)
@router.get("/login", include_in_schema=False)
def react_app_known_route(request: Request) -> FileResponse:
    """Return the React app entrypoint for known frontend routes."""

    return _react_index(request)


@fallback_router.get("/{path:path}", include_in_schema=False)
def react_app_fallback(path: str, request: Request) -> FileResponse:
    """Return the React app entrypoint for frontend routes."""

    first_segment = path.split("/", maxsplit=1)[0]
    if first_segment not in FRONTEND_ROUTE_PREFIXES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return _react_index(request)
