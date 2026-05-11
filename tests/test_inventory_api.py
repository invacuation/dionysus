from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.inventory.assets import create_scan_target
from dionysus.inventory.projects import create_project
from dionysus.models import Base
from dionysus.models.audit import AuditLogEvent
from dionysus.models.findings import (
    FindingComment,
    FindingStatusChangeRequest,
    ImportAttempt,
    ImportStatus,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
    Scan,
    ScannerKind,
)
from dionysus.models.identity import PermissionEffect, PrincipalType
from dionysus.models.inventory import AssetNode, Project


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(
        AppSettings(
            environment=Environment.TEST,
            database_url="sqlite:///:memory:",
            bootstrap_admin_username="admin",
            bootstrap_admin_password="change-me-now-please",  # noqa: S106 - test fixture password
        )
    )
    app.state.session_factory = session_factory
    return TestClient(app)


def _login_user(client: TestClient, session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        user_id = user.id
        session.commit()

    response = client.post(
        "/api/auth/session",
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return user_id


def _grant_permission(
    session_factory: sessionmaker[Session],
    *,
    user_id: str,
    permission: str,
    scope_type: str | None = None,
    scope_id: str | None = None,
) -> None:
    with session_factory() as session:
        assign_permission(
            session,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission=permission,
            effect=PermissionEffect.ALLOW,
            scope_type=scope_type,
            scope_id=scope_id,
        )
        session.commit()


def _login_user_with_permission(
    client: TestClient,
    session_factory: sessionmaker[Session],
    *,
    permission: str,
    scope_type: str | None = None,
    scope_id: str | None = None,
) -> str:
    user_id = _login_user(client, session_factory)
    _grant_permission(
        session_factory,
        user_id=user_id,
        permission=permission,
        scope_type=scope_type,
        scope_id=scope_id,
    )
    return user_id


def test_inventory_api_projects_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)

        response = client.get("/api/projects")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_inventory_api_assets_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)

        response = client.get(f"/api/projects/{project_id}/assets")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_inventory_api_project_create_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)

        response = client.post("/api/projects", json={"slug": "alpha", "name": "Alpha"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_inventory_api_projects_returns_authenticated_project_list(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            beta = create_project(session, slug="beta", name="Beta")
            alpha = create_project(
                session,
                slug="alpha",
                name="Alpha",
                description="Primary inventory",
                sla_tracking_enabled=False,
                sla_reporting_enabled=False,
                require_peer_review_for_status_changes=True,
                grace_period_enabled=True,
                grace_period_percent=50,
            )
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory)
        _grant_permission(
            session_factory,
            user_id=user_id,
            permission="project:view",
            scope_type="project",
            scope_id=alpha.id,
        )
        _grant_permission(
            session_factory,
            user_id=user_id,
            permission="project:view",
            scope_type="project",
            scope_id=beta.id,
        )

        response = client.get("/api/projects")

    assert response.status_code == 200
    assert response.json() == {
        "projects": [
            {
                "id": alpha.id,
                "slug": "alpha",
                "name": "Alpha",
                "description": "Primary inventory",
                "sla_tracking_enabled": False,
                "sla_reporting_enabled": False,
                "require_peer_review_for_status_changes": True,
                "grace_period_enabled": True,
                "grace_period_percent": 50,
            },
            {
                "id": beta.id,
                "slug": "beta",
                "name": "Beta",
                "description": None,
                "sla_tracking_enabled": True,
                "sla_reporting_enabled": True,
                "require_peer_review_for_status_changes": False,
                "grace_period_enabled": False,
                "grace_period_percent": 100,
            },
        ],
    }


def test_inventory_api_projects_filters_inaccessible_projects(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha = create_project(session, slug="alpha", name="Alpha")
            create_project(session, slug="beta", name="Beta")
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory)
        _grant_permission(
            session_factory,
            user_id=user_id,
            permission="project:view",
            scope_type="project",
            scope_id=alpha.id,
        )

        response = client.get("/api/projects")

    assert response.status_code == 200
    assert response.json()["projects"] == [
        {
            "id": alpha.id,
            "slug": "alpha",
            "name": "Alpha",
            "description": None,
            "sla_tracking_enabled": True,
            "sla_reporting_enabled": True,
            "require_peer_review_for_status_changes": False,
            "grace_period_enabled": False,
            "grace_period_percent": 100,
        }
    ]


def test_inventory_api_project_update_changes_grace_period_settings(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="project:update",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.patch(
            f"/api/projects/{project_id}",
            json={"grace_period_enabled": True, "grace_period_percent": 70},
        )
        invalid_response = client.patch(
            f"/api/projects/{project_id}",
            json={"grace_period_percent": 0},
        )
        with session_factory() as session:
            updated_project = session.get(Project, project_id)
            audit_event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "inventory.project.update")
            )

    assert response.status_code == 200
    assert response.json()["grace_period_enabled"] is True
    assert response.json()["grace_period_percent"] == 70
    assert invalid_response.status_code == 400
    assert updated_project is not None
    assert updated_project.grace_period_enabled is True
    assert updated_project.grace_period_percent == 70
    assert audit_event is not None
    assert set(audit_event.metadata_json["changed_fields"]) == {
        "grace_period_enabled",
        "grace_period_percent",
    }


def test_inventory_api_assets_returns_authenticated_project_assets(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            create_scan_target(
                session,
                project=project,
                folder_path="images/releases",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="project:view",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.get(f"/api/projects/{project_id}/assets")

    assert response.status_code == 200
    assert response.json() == {
        "project_id": project_id,
        "assets": [
            {
                "id": response.json()["assets"][0]["id"],
                "parent_id": None,
                "path": "images",
                "type": "folder",
                "name": "images",
                "target_ref": None,
                "scan_label": None,
                "sla_tracking_enabled": None,
                "sla_reporting_enabled": None,
                "sort_order": 0,
            },
            {
                "id": response.json()["assets"][1]["id"],
                "parent_id": response.json()["assets"][0]["id"],
                "path": "images/releases",
                "type": "folder",
                "name": "releases",
                "target_ref": None,
                "scan_label": None,
                "sla_tracking_enabled": None,
                "sla_reporting_enabled": None,
                "sort_order": 0,
            },
            {
                "id": response.json()["assets"][2]["id"],
                "parent_id": response.json()["assets"][1]["id"],
                "path": "images/releases/Production Image",
                "type": "scan_target",
                "name": "Production Image",
                "target_ref": "registry.example.test/app:2026.05",
                "scan_label": None,
                "sla_tracking_enabled": None,
                "sla_reporting_enabled": None,
                "sort_order": 0,
            },
        ],
    }


def test_inventory_api_assets_describes_scan_target_report_kind(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            target = create_scan_target(
                session,
                project=project,
                folder_path="images/releases",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            session.add(
                Scan(
                    project=project,
                    scan_target=target,
                    scanner_kind=ScannerKind.TRIVY,
                    report_kind="trivy-json",
                    parser_version="1",
                    created_at=datetime(2026, 5, 7, tzinfo=UTC),
                )
            )
            session.add(
                Scan(
                    project=project,
                    scan_target=target,
                    scanner_kind=ScannerKind.TRIVY,
                    report_kind="trivy-image-json",
                    parser_version="1",
                    created_at=datetime(2026, 5, 7, tzinfo=UTC) + timedelta(days=1),
                )
            )
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="project:view",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.get(f"/api/projects/{project_id}/assets")

    assert response.status_code == 200
    scan_target = response.json()["assets"][2]
    assert scan_target["type"] == "scan_target"
    assert scan_target["scan_label"] == "Trivy Image Scan"


def test_inventory_api_assets_requires_project_view_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get(f"/api/projects/{project_id}/assets")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_inventory_api_assets_returns_404_for_unknown_project(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(client, session_factory, permission="project:create")

        response = client.get("/api/projects/missing/assets")

    assert response.status_code == 404
    assert response.json() == {"detail": "Project not found"}


def test_inventory_api_project_create_returns_project_and_records_audit_event(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(client, session_factory, permission="project:create")

        response = client.post(
            "/api/projects",
            json={
                "slug": "alpha",
                "name": " Alpha Inventory ",
                "description": "Primary inventory",
                "sla_tracking_enabled": False,
                "sla_reporting_enabled": False,
                "require_peer_review_for_status_changes": True,
                "grace_period_enabled": True,
                "grace_period_percent": 50,
            },
        )
        with session_factory() as session:
            event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "inventory.project.create")
            )

    assert response.status_code == 201
    body = response.json()
    assert body == {
        "id": body["id"],
        "slug": "alpha",
        "name": "Alpha Inventory",
        "description": "Primary inventory",
        "sla_tracking_enabled": False,
        "sla_reporting_enabled": False,
        "require_peer_review_for_status_changes": True,
        "grace_period_enabled": True,
        "grace_period_percent": 50,
    }
    assert event is not None
    assert event.event_type == "inventory.project.create"
    assert event.target_type == "project"
    assert event.target_id == body["id"]
    assert event.project_id == body["id"]
    assert event.actor_principal_type == "user"
    assert event.actor_display == "Alice"
    assert event.metadata_json == {"slug": "alpha", "name": "Alpha Inventory"}


def test_inventory_api_project_create_returns_409_for_duplicate_slug(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            create_project(session, slug="alpha", name="Alpha")
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(client, session_factory, permission="project:create")

        response = client.post("/api/projects", json={"slug": "alpha", "name": "Alpha Copy"})

    assert response.status_code == 409
    assert response.json() == {"detail": "Project slug or name already exists"}


def test_inventory_api_project_create_returns_400_for_service_validation(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(client, session_factory, permission="project:create")

        response = client.post(
            "/api/projects",
            json={"slug": "bad slug", "name": "Bad Slug"},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "project slug must not contain whitespace"}


def test_inventory_api_project_peer_review_setting_patch_updates_and_audits(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="project:update",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.patch(
            f"/api/projects/{project_id}",
            json={"require_peer_review_for_status_changes": True},
        )
        with session_factory() as session:
            updated_project = session.get(type(project), project_id)
            event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "inventory.project.update")
            )

    assert response.status_code == 200
    body = response.json()
    assert body["require_peer_review_for_status_changes"] is True
    assert updated_project is not None
    assert updated_project.require_peer_review_for_status_changes is True
    assert event is not None
    assert event.target_type == "project"
    assert event.target_id == project_id
    assert event.project_id == project_id
    assert event.metadata_json == {
        "changed_fields": ["require_peer_review_for_status_changes"],
        "changes": {
            "require_peer_review_for_status_changes": {
                "old": False,
                "new": True,
            },
        },
    }


def test_inventory_api_folder_resolve_creates_missing_folders_and_records_audit_event(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="asset:create",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.post(
            f"/api/projects/{project_id}/folders",
            json={"path": " images / releases "},
        )
        second_response = client.post(
            f"/api/projects/{project_id}/folders",
            json={"path": "images/releases"},
        )
        with session_factory() as session:
            assets = session.scalars(select(AssetNode).order_by(AssetNode.path)).all()
            events = session.scalars(
                select(AuditLogEvent)
                .where(AuditLogEvent.event_type == "inventory.folder.resolve")
                .order_by(AuditLogEvent.created_at)
            ).all()

    assert response.status_code == 201
    body = response.json()
    assert body == {
        "id": body["id"],
        "parent_id": assets[0].id,
        "path": "images/releases",
        "type": "folder",
        "name": "releases",
        "target_ref": None,
        "scan_label": None,
        "sla_tracking_enabled": None,
        "sla_reporting_enabled": None,
        "sort_order": 0,
    }
    assert second_response.status_code == 201
    assert second_response.json()["id"] == body["id"]
    assert [asset.path for asset in assets] == ["images", "images/releases"]
    assert [event.event_type for event in events] == [
        "inventory.folder.resolve",
        "inventory.folder.resolve",
    ]
    assert events[0].target_type == "asset_node"
    assert events[0].target_id == body["id"]
    assert events[0].project_id == project_id
    assert events[0].metadata_json == {"path": "images/releases", "name": "releases"}


def test_inventory_api_folder_resolve_rejects_unknown_project_and_invalid_path(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="asset:create",
            scope_type="project",
            scope_id=project_id,
        )

        missing_response = client.post("/api/projects/missing/folders", json={"path": "images"})
        invalid_response = client.post(
            f"/api/projects/{project_id}/folders",
            json={"path": "images//releases"},
        )

    assert missing_response.status_code == 404
    assert missing_response.json() == {"detail": "Project not found"}
    assert invalid_response.status_code == 400
    assert invalid_response.json() == {"detail": "folder path must not contain empty segments"}


def test_inventory_api_scan_target_create_returns_asset_and_records_audit_event(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="asset:create",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.post(
            f"/api/projects/{project_id}/scan-targets",
            json={
                "folder_path": "images/releases",
                "name": "Production Image",
                "target_ref": "registry.example.test/app:2026.05",
                "metadata": {"source": "api"},
            },
        )
        with session_factory() as session:
            event = session.scalar(
                select(AuditLogEvent).where(
                    AuditLogEvent.event_type == "inventory.scan_target.create"
                )
            )

    assert response.status_code == 201
    body = response.json()
    assert body["path"] == "images/releases/Production Image"
    assert body["type"] == "scan_target"
    assert body["target_ref"] == "registry.example.test/app:2026.05"
    assert event is not None
    assert event.target_type == "asset_node"
    assert event.target_id == body["id"]
    assert event.project_id == project_id
    assert event.metadata_json == {
        "folder_path": "images/releases",
        "name": "Production Image",
        "node_type": "scan_target",
    }


def test_inventory_api_scan_target_create_returns_409_for_duplicate_sibling(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            create_scan_target(
                session,
                project=project,
                folder_path="images",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="asset:create",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.post(
            f"/api/projects/{project_id}/scan-targets",
            json={
                "folder_path": "images",
                "name": "Production Image",
                "target_ref": "registry.example.test/app:2026.06",
            },
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Asset path or sibling name already exists"}


def test_inventory_api_asset_patch_renames_moves_and_updates_sla_overrides(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            target = create_scan_target(
                session,
                project=project,
                folder_path="images/releases",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            archive = create_scan_target(
                session,
                project=project,
                folder_path="archive",
                name="Archive Image",
                target_ref="registry.example.test/archive:2026.05",
            )
            project_id = project.id
            target_id = target.id
            archive_parent_id = archive.parent_id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="asset:update",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.patch(
            f"/api/projects/{project_id}/assets/{target_id}",
            json={
                "name": "Renamed Image",
                "parent_id": archive_parent_id,
                "sla_tracking_enabled": False,
                "sla_reporting_enabled": True,
            },
        )
        with session_factory() as session:
            event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "inventory.asset.update")
            )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == target_id
    assert body["parent_id"] == archive_parent_id
    assert body["path"] == "archive/Renamed Image"
    assert body["name"] == "Renamed Image"
    assert body["sla_tracking_enabled"] is False
    assert body["sla_reporting_enabled"] is True
    assert event is not None
    assert event.target_type == "asset_node"
    assert event.target_id == target_id
    assert event.project_id == project_id
    assert event.metadata_json == {
        "changed_fields": [
            "name",
            "parent_id",
            "sla_tracking_enabled",
            "sla_reporting_enabled",
        ]
    }


def test_inventory_api_asset_patch_rejects_missing_asset_and_invalid_parent(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            other_project = create_project(session, slug="beta", name="Beta")
            target = create_scan_target(
                session,
                project=project,
                folder_path="images",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            other_target = create_scan_target(
                session,
                project=other_project,
                folder_path="images",
                name="Other Image",
                target_ref="registry.example.test/other:2026.05",
            )
            project_id = project.id
            target_id = target.id
            other_parent_id = other_target.parent_id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user_with_permission(
            client,
            session_factory,
            permission="asset:update",
            scope_type="project",
            scope_id=project_id,
        )

        missing_project_response = client.patch(
            f"/api/projects/missing/assets/{target_id}",
            json={"name": "Renamed Image"},
        )
        missing_asset_response = client.patch(
            f"/api/projects/{project_id}/assets/missing",
            json={"name": "Renamed Image"},
        )
        invalid_parent_response = client.patch(
            f"/api/projects/{project_id}/assets/{target_id}",
            json={"parent_id": other_parent_id},
        )

    assert missing_project_response.status_code == 404
    assert missing_project_response.json() == {"detail": "Project not found"}
    assert missing_asset_response.status_code == 404
    assert missing_asset_response.json() == {"detail": "Asset not found"}
    assert invalid_parent_response.status_code == 400
    assert invalid_parent_response.json() == {
        "detail": "asset parent must belong to the same project"
    }


def test_inventory_api_project_delete_requires_project_delete_permission(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.delete(f"/api/projects/{project_id}")
        with session_factory() as session:
            project_still_exists = session.get(type(project), project_id) is not None

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert project_still_exists is True


def test_inventory_api_project_delete_removes_dependents_and_records_audit_event(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            target = create_scan_target(
                session,
                project=project,
                folder_path="images/releases",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            _create_finding_graph(session, project=project, target=target)
            project_id = project.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory)
        _grant_permission(
            session_factory,
            user_id=user_id,
            permission="project:delete",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.delete(f"/api/projects/{project_id}")
        with session_factory() as session:
            event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "inventory.project.delete")
            )
            remaining_counts = _inventory_dependency_counts(session)

    assert response.status_code == 204
    assert response.content == b""
    assert remaining_counts == {
        "projects": 0,
        "asset_nodes": 0,
        "import_attempts": 0,
        "scans": 0,
        "raw_finding_instances": 0,
        "finding_comments": 0,
        "finding_status_change_requests": 0,
        "project_vulnerability_groups": 0,
    }
    assert event is not None
    assert event.target_type == "project"
    assert event.target_id == project_id
    assert event.project_id == project_id
    assert event.metadata_json == {
        "slug": "alpha",
        "name": "Alpha",
        "deleted_asset_count": 3,
    }


def test_inventory_api_asset_delete_removes_descendants_and_dependent_scan_data(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            deleted_target = create_scan_target(
                session,
                project=project,
                folder_path="images/releases",
                name="Production Image",
                target_ref="registry.example.test/app:2026.05",
            )
            kept_target = create_scan_target(
                session,
                project=project,
                folder_path="archive",
                name="Archive Image",
                target_ref="registry.example.test/archive:2026.05",
            )
            _create_finding_graph(session, project=project, target=deleted_target)
            _create_finding_graph(
                session,
                project=project,
                target=kept_target,
                primary_identifier="CVE-2026-0002",
            )
            project_id = project.id
            releases_folder = deleted_target.parent
            assert releases_folder is not None
            folder_id = releases_folder.parent_id
            assert folder_id is not None
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory)
        _grant_permission(session_factory, user_id=user_id, permission="admin:*")

        response = client.delete(f"/api/projects/{project_id}/assets/{folder_id}")
        with session_factory() as session:
            event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "inventory.asset.delete")
            )
            remaining_asset_paths = session.scalars(
                select(AssetNode.path).order_by(AssetNode.path)
            ).all()
            remaining_counts = _inventory_dependency_counts(session)

    assert response.status_code == 204
    assert remaining_asset_paths == ["archive", "archive/Archive Image"]
    assert remaining_counts == {
        "projects": 1,
        "asset_nodes": 2,
        "import_attempts": 1,
        "scans": 1,
        "raw_finding_instances": 1,
        "finding_comments": 1,
        "finding_status_change_requests": 1,
        "project_vulnerability_groups": 2,
    }
    assert event is not None
    assert event.target_type == "asset_node"
    assert event.target_id == folder_id
    assert event.project_id == project_id
    assert event.metadata_json == {
        "path": "images",
        "name": "images",
        "node_type": "folder",
        "deleted_node_count": 3,
    }


def test_inventory_api_asset_delete_returns_404_for_cross_project_asset(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = create_project(session, slug="alpha", name="Alpha")
            other_project = create_project(session, slug="beta", name="Beta")
            other_target = create_scan_target(
                session,
                project=other_project,
                folder_path="images",
                name="Other Image",
                target_ref="registry.example.test/other:2026.05",
            )
            project_id = project.id
            other_target_id = other_target.id
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory)
        _grant_permission(
            session_factory,
            user_id=user_id,
            permission="asset:delete",
            scope_type="project",
            scope_id=project_id,
        )

        response = client.delete(f"/api/projects/{project_id}/assets/{other_target_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Asset not found"}


def _create_finding_graph(
    session: Session,
    *,
    project: Project,
    target: AssetNode,
    primary_identifier: str = "CVE-2026-0001",
) -> None:
    import_attempt = ImportAttempt(
        project=project,
        asset_node=target,
        status=ImportStatus.SUCCESS,
        parser_name="trivy-json",
    )
    scan = Scan(
        project=project,
        scan_target=target,
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image",
        parser_version="1",
    )
    finding = RawFindingInstance(
        project=project,
        scan=scan,
        scan_target=target,
        scanner_kind=ScannerKind.TRIVY,
        scanner_finding_id=primary_identifier,
        dedupe_key=primary_identifier,
        identifiers_json=[primary_identifier],
        primary_identifier=primary_identifier,
        severity="HIGH",
        cvss_json={},
        package_name="openssl",
        package_version="1.0.0",
        fixed_version="1.0.1",
        artifact_name=target.name,
        artifact_type="container_image",
        artifact_path=target.path,
        references_json=[],
        source_json={},
    )
    FindingComment(
        project=project,
        finding=finding,
        author_principal_type="user",
        author_principal_id="alice",
        body="Needs review.",
    )
    FindingStatusChangeRequest(
        project=project,
        finding=finding,
        requester_principal_type="user",
        requester_principal_id="alice",
        from_status="open",
        to_status="fixed",
        state="pending",
    )
    vulnerability_group = ProjectVulnerabilityGroup(
        project=project,
        primary_identifier=primary_identifier,
        severity="HIGH",
        status="open",
        dedupe_key=primary_identifier,
    )
    session.add(import_attempt)
    session.add(scan)
    session.add(vulnerability_group)
    session.flush()


def _inventory_dependency_counts(session: Session) -> dict[str, int]:
    return {
        "projects": _count(session, "projects"),
        "asset_nodes": _count(session, "asset_nodes"),
        "import_attempts": _count(session, "import_attempts"),
        "scans": _count(session, "scans"),
        "raw_finding_instances": _count(session, "raw_finding_instances"),
        "finding_comments": _count(session, "finding_comments"),
        "finding_status_change_requests": _count(session, "finding_status_change_requests"),
        "project_vulnerability_groups": _count(session, "project_vulnerability_groups"),
    }


def _count(session: Session, table_name: str) -> int:
    table = Base.metadata.tables[table_name]
    return int(session.scalar(select(func.count()).select_from(table)) or 0)
