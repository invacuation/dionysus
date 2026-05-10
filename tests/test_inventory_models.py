import importlib.util
from pathlib import Path
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import DateTime, UniqueConstraint, create_engine, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from dionysus.models import AppSecuritySettings as ExportedAppSecuritySettings
from dionysus.models import AssetNode as ExportedAssetNode
from dionysus.models import AssetNodeType as ExportedAssetNodeType
from dionysus.models import Project as ExportedProject
from dionysus.models.base import Base
from dionysus.models.inventory import AssetNode, AssetNodeType, Project
from dionysus.models.settings import AppSecuritySettings


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_inventory_models_create_expected_tables() -> None:
    engine = create_engine("sqlite:///:memory:")

    Base.metadata.create_all(engine)

    table_names = set(inspect(engine).get_table_names())
    assert {"projects", "asset_nodes", "app_security_settings"}.issubset(table_names)


def test_inventory_models_include_timestamp_mixin_columns() -> None:
    project_created_at_type = Project.__table__.c.created_at.type
    project_updated_at_type = Project.__table__.c.updated_at.type
    asset_created_at_type = AssetNode.__table__.c.created_at.type
    asset_updated_at_type = AssetNode.__table__.c.updated_at.type

    assert isinstance(project_created_at_type, DateTime)
    assert isinstance(project_updated_at_type, DateTime)
    assert isinstance(asset_created_at_type, DateTime)
    assert isinstance(asset_updated_at_type, DateTime)
    assert project_created_at_type.timezone is True
    assert project_updated_at_type.timezone is True
    assert asset_created_at_type.timezone is True
    assert asset_updated_at_type.timezone is True


def test_inventory_model_table_names_are_stable() -> None:
    assert Project.__tablename__ == "projects"
    assert AssetNode.__tablename__ == "asset_nodes"


def test_asset_node_unique_constraint_names_match_migration() -> None:
    unique_constraint_names = {
        constraint.name
        for constraint in AssetNode.__mapper__.local_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert {
        "uq_asset_nodes_project_path",
        "uq_asset_nodes_project_parent_name",
    }.issubset(unique_constraint_names)


def test_inventory_models_are_exported_from_models_package() -> None:
    assert ExportedProject is Project
    assert ExportedAssetNode is AssetNode
    assert ExportedAssetNodeType is AssetNodeType
    assert ExportedAppSecuritySettings is AppSecuritySettings


def test_asset_node_type_includes_required_values() -> None:
    assert {node_type.value for node_type in AssetNodeType} >= {
        "folder",
        "branch",
        "release",
        "tag",
        "container_image",
        "manifest",
        "file",
        "scan_target",
        "other",
    }


def test_project_and_asset_ids_are_uuid_like_non_empty_strings() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        asset = AssetNode(
            project=project,
            node_type=AssetNodeType.FOLDER,
            name="src",
            path="src",
        )
        session.add(project)
        session.add(asset)
        session.flush()

        assert isinstance(project.id, str)
        assert isinstance(asset.id, str)
        assert UUID(project.id)
        assert UUID(asset.id)


def test_project_defaults_cover_sla_reporting_and_grace_periods() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        session.add(project)
        session.flush()

        assert project.sla_tracking_enabled is True
        assert project.sla_reporting_enabled is True
        assert project.require_peer_review_for_status_changes is False
        assert project.grace_period_enabled is False
        assert project.grace_period_percent == 100
        assert project.created_at is not None
        assert project.updated_at is not None


def test_project_allows_explicit_sla_reporting_and_grace_period_values() -> None:
    with _session() as session:
        project = Project(
            slug="alpha",
            name="Alpha",
            description="Inventory for Alpha",
            sla_tracking_enabled=False,
            sla_reporting_enabled=False,
            require_peer_review_for_status_changes=True,
            grace_period_enabled=True,
            grace_period_percent=125,
        )
        session.add(project)
        session.flush()

        assert project.description == "Inventory for Alpha"
        assert project.sla_tracking_enabled is False
        assert project.sla_reporting_enabled is False
        assert project.require_peer_review_for_status_changes is True
        assert project.grace_period_enabled is True
        assert project.grace_period_percent == 125


def test_app_security_settings_defaults_to_not_forcing_peer_review() -> None:
    with _session() as session:
        settings = AppSecuritySettings()
        session.add(settings)
        session.flush()

        assert settings.id == "default"
        assert settings.force_peer_review_for_status_changes is False
        assert settings.created_at is not None
        assert settings.updated_at is not None


def test_asset_node_defaults_and_explicit_inventory_fields_are_persisted() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        defaulted = AssetNode(
            project=project,
            node_type=AssetNodeType.FOLDER,
            name="src",
            path="src",
        )
        explicit = AssetNode(
            project=project,
            node_type=AssetNodeType.SCAN_TARGET,
            name="main-image",
            path="images/main",
            target_ref="registry.example.test/app:main",
            metadata_json={"digest": "sha256:abc123", "criticality": "high"},
            sla_tracking_enabled=False,
            sla_reporting_enabled=True,
            sort_order=20,
        )
        session.add_all([defaulted, explicit])
        session.flush()

        assert defaulted.metadata_json == {}
        assert defaulted.sla_tracking_enabled is None
        assert defaulted.sla_reporting_enabled is None
        assert defaulted.sort_order == 0
        assert defaulted.created_at is not None
        assert defaulted.updated_at is not None
        assert explicit.target_ref == "registry.example.test/app:main"
        assert explicit.metadata_json == {"digest": "sha256:abc123", "criticality": "high"}
        assert explicit.sla_tracking_enabled is False
        assert explicit.sla_reporting_enabled is True
        assert explicit.sort_order == 20


def test_duplicate_project_slugs_are_rejected() -> None:
    with _session() as session:
        session.add_all(
            [
                Project(slug="alpha", name="Alpha"),
                Project(slug="alpha", name="Duplicate Alpha"),
            ]
        )

        with pytest.raises(IntegrityError):
            session.flush()


def test_asset_node_paths_are_unique_within_a_project_only() -> None:
    with _session() as session:
        alpha = Project(slug="alpha", name="Alpha")
        beta = Project(slug="beta", name="Beta")
        session.add_all(
            [
                alpha,
                beta,
                AssetNode(
                    project=alpha,
                    node_type=AssetNodeType.FILE,
                    name="README.md",
                    path="README.md",
                ),
                AssetNode(
                    project=beta,
                    node_type=AssetNodeType.FILE,
                    name="README.md",
                    path="README.md",
                ),
            ]
        )
        session.flush()

        session.add(
            AssetNode(
                project=alpha,
                node_type=AssetNodeType.FILE,
                name="README-copy.md",
                path="README.md",
            )
        )

        with pytest.raises(IntegrityError):
            session.flush()


def test_asset_node_rejects_invalid_node_type_values() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        session.add(project)
        session.flush()

        session.add(
            AssetNode(
                project=project,
                node_type="not-a-real-node-type",
                name="invalid",
                path="invalid",
            )
        )

        with pytest.raises(IntegrityError):
            session.flush()


def test_asset_node_parent_child_tree_relationships_and_cascade_delete() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        root = AssetNode(
            project=project,
            node_type=AssetNodeType.FOLDER,
            name="src",
            path="src",
        )
        child = AssetNode(
            project=project,
            parent=root,
            node_type=AssetNodeType.FOLDER,
            name="api",
            path="src/api",
        )
        grandchild = AssetNode(
            project=project,
            parent=child,
            node_type=AssetNodeType.FILE,
            name="README.md",
            path="src/api/README.md",
        )
        sibling_parent = AssetNode(
            project=project,
            node_type=AssetNodeType.FOLDER,
            name="docs",
            path="docs",
        )
        same_child_name_under_other_parent = AssetNode(
            project=project,
            parent=sibling_parent,
            node_type=AssetNodeType.FILE,
            name="README.md",
            path="docs/README.md",
        )
        session.add_all(
            [
                root,
                child,
                grandchild,
                sibling_parent,
                same_child_name_under_other_parent,
            ]
        )
        session.flush()

        assert child.parent is root
        assert grandchild.parent is child
        assert child in root.children
        assert grandchild in child.children
        assert same_child_name_under_other_parent in sibling_parent.children
        assert {asset.path for asset in project.assets} == {
            "src",
            "src/api",
            "src/api/README.md",
            "docs",
            "docs/README.md",
        }

        session.delete(child)
        session.flush()

        remaining_paths = set(session.scalars(select(AssetNode.path)))
        assert remaining_paths == {"src", "docs", "docs/README.md"}


def test_duplicate_sibling_asset_names_are_rejected() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        parent = AssetNode(
            project=project,
            node_type=AssetNodeType.FOLDER,
            name="src",
            path="src",
        )
        session.add(parent)
        session.flush()

        session.add_all(
            [
                AssetNode(
                    project=project,
                    parent=parent,
                    node_type=AssetNodeType.FILE,
                    name="pyproject.toml",
                    path="src/pyproject.toml",
                ),
                AssetNode(
                    project=project,
                    parent=parent,
                    node_type=AssetNodeType.FILE,
                    name="pyproject.toml",
                    path="src/duplicate-pyproject.toml",
                ),
            ]
        )

        with pytest.raises(IntegrityError):
            session.flush()


def test_project_asset_inventory_migration_revision_chain_is_stable() -> None:
    migration_path = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0003_project_asset_inventory.py"
    )
    spec = importlib.util.spec_from_file_location(
        "migration_0003_project_asset_inventory",
        migration_path,
    )
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0003_project_asset_inventory"
    assert migration.down_revision == "0002_machine_refresh_tokens"


def test_project_asset_inventory_migration_creates_and_drops_tables(
    monkeypatch,
    tmp_path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'inventory.db'}"
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    project_root = Path(__file__).parents[1]
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))

    command.upgrade(config, "0003_project_asset_inventory")

    engine = create_engine(database_url)
    try:
        table_names = set(inspect(engine).get_table_names())
        assert {"projects", "asset_nodes"}.issubset(table_names)

        command.downgrade(config, "0002_machine_refresh_tokens")

        table_names = set(inspect(engine).get_table_names())
        assert "projects" not in table_names
        assert "asset_nodes" not in table_names
    finally:
        engine.dispose()


def test_duplicate_root_asset_names_are_rejected() -> None:
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        session.add(project)
        session.flush()

        session.add_all(
            [
                AssetNode(
                    project=project,
                    node_type=AssetNodeType.FOLDER,
                    name="src",
                    path="src",
                ),
                AssetNode(
                    project=project,
                    node_type=AssetNodeType.FOLDER,
                    name="src",
                    path="alternate-src",
                ),
            ]
        )

        with pytest.raises(IntegrityError):
            session.flush()
