"""JSON API router composition."""

from fastapi import APIRouter

from dionysus.api.access import router as access_router
from dionysus.api.admin_imports import router as admin_imports_router
from dionysus.api.audit import router as audit_router
from dionysus.api.auth import router as auth_router
from dionysus.api.findings import router as findings_router
from dionysus.api.imports import router as imports_router
from dionysus.api.inventory import router as inventory_router
from dionysus.api.machine_credentials import router as machine_credentials_router
from dionysus.api.oauth import router as oauth_router
from dionysus.api.overview import router as overview_router
from dionysus.api.permission_test import router as permission_test_router
from dionysus.api.security_settings import router as security_settings_router
from dionysus.api.sessions import router as sessions_router

router = APIRouter()
router.include_router(access_router)
router.include_router(admin_imports_router)
router.include_router(audit_router)
router.include_router(auth_router)
router.include_router(findings_router)
router.include_router(imports_router)
router.include_router(inventory_router)
router.include_router(machine_credentials_router)
router.include_router(oauth_router)
router.include_router(overview_router)
router.include_router(permission_test_router)
router.include_router(security_settings_router)
router.include_router(sessions_router)
