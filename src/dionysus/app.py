"""FastAPI application factory for Dionysus."""

from fastapi import FastAPI
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from dionysus.api import router as api_router
from dionysus.config import AppSettings
from dionysus.db import create_engine_from_url, create_session_factory
from dionysus.frontend import (
    default_frontend_dist,
    mount_frontend_assets,
)
from dionysus.frontend import (
    fallback_router as frontend_fallback_router,
)
from dionysus.frontend import (
    router as frontend_router,
)
from dionysus.identity.bootstrap import BootstrapAdminError, bootstrap_admin_from_settings
from dionysus.middleware.request_size import RequestBodyLimitMiddleware
from dionysus.routes.health import router as health_router

SCHEMA_NOT_READY_MESSAGE = (
    "startup bootstrap failed: database schema is not up to date; "
    "run migrations and retry"
)


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Create and configure the Dionysus FastAPI application.

    Args:
        settings: Optional settings object to attach to application state. When
            omitted, settings are loaded from the environment.

    Returns:
        A configured FastAPI application with routes registered.
    """

    resolved_settings = settings or AppSettings()
    app = FastAPI(title="Dionysus")
    app.state.settings = resolved_settings
    app.state.engine = create_engine_from_url(resolved_settings.database_url)
    app.state.session_factory = create_session_factory(app.state.engine)
    _bootstrap_admin(app.state.session_factory, resolved_settings)
    app.state.frontend_dist = default_frontend_dist()
    mount_frontend_assets(app, app.state.frontend_dist)
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=resolved_settings.max_report_upload_bytes,
    )
    app.include_router(api_router)
    app.include_router(health_router)
    app.include_router(frontend_router)
    app.include_router(frontend_fallback_router)
    return app


def _bootstrap_admin(
    session_factory: sessionmaker,
    settings: AppSettings,
) -> None:
    """Run initial administrator bootstrap inside an app startup transaction."""

    with session_factory() as session:
        try:
            bootstrap_admin_from_settings(session, settings)
            session.commit()
        except OperationalError as exc:
            session.rollback()
            raise BootstrapAdminError(SCHEMA_NOT_READY_MESSAGE) from exc
        except Exception:
            session.rollback()
            raise
