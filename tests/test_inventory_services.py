import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dionysus.inventory.assets import (
    create_asset_node,
    create_scan_target,
    list_project_assets,
    move_asset_node,
    normalize_folder_path,
    rename_asset_node,
    resolve_folder_path,
    set_asset_sla_overrides,
)
from dionysus.inventory.projects import (
    create_project,
    get_project,
    get_project_by_slug,
    list_projects,
)
from dionysus.models.inventory import AssetNode, AssetNodeType


def test_create_project_creates_and_flushes_project_with_defaults(db_session: Session) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")

    assert project.id is not None
    assert project.slug == "alpha"
    assert project.name == "Alpha"
    assert project.description is None
    assert project.sla_tracking_enabled is True
    assert project.sla_reporting_enabled is True
    assert project.grace_period_enabled is False
    assert project.grace_period_percent == 100


def test_project_lookup_and_listing_are_deterministic(db_session: Session) -> None:
    beta = create_project(db_session, slug="beta", name="Beta")
    alpha = create_project(db_session, slug="alpha", name="Alpha")
    untitled = create_project(db_session, slug="untitled", name="Alpha")

    assert get_project_by_slug(db_session, "alpha") is alpha
    assert get_project_by_slug(db_session, "missing") is None
    assert get_project(db_session, beta.id) is beta
    assert get_project(db_session, "missing") is None
    assert list_projects(db_session) == [alpha, untitled, beta]


@pytest.mark.parametrize(
    ("slug", "name", "grace_period_percent", "message"),
    [
        ("", "Alpha", 100, "project slug must be non-empty"),
        ("has whitespace", "Alpha", 100, "project slug must not contain whitespace"),
        ("alpha", "", 100, "project name must be non-empty"),
        (
            "alpha",
            "Alpha",
            0,
            "grace period percent must be positive",
        ),
    ],
)
def test_create_project_validates_reusable_inputs(
    db_session: Session,
    slug: str,
    name: str,
    grace_period_percent: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        create_project(
            db_session,
            slug=slug,
            name=name,
            grace_period_percent=grace_period_percent,
        )


def test_resolve_folder_path_creates_nested_folders_and_reuses_them(
    db_session: Session,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")

    folder = resolve_folder_path(db_session, project, " loren / ipsum ")
    same_folder = resolve_folder_path(db_session, project, "loren/ipsum")

    assert folder is same_folder
    assert folder.name == "ipsum"
    assert folder.path == "loren/ipsum"
    assert folder.node_type == AssetNodeType.FOLDER
    assert folder.parent is not None
    assert folder.parent.name == "loren"
    assert folder.parent.path == "loren"
    assert folder.parent.node_type == AssetNodeType.FOLDER
    assert len(db_session.scalars(select(AssetNode)).all()) == 2


def test_resolve_folder_path_rejects_existing_non_folder_path(
    db_session: Session,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")
    create_asset_node(
        db_session,
        project=project,
        parent=None,
        node_type=AssetNodeType.SCAN_TARGET,
        name="src",
        target_ref="repo/src",
    )

    with pytest.raises(ValueError, match="folder path conflicts with existing asset node"):
        resolve_folder_path(db_session, project, "src")


@pytest.mark.parametrize(
    "path",
    [
        "",
        " ",
        "/loren",
        "loren/",
        "loren//ipsum",
        "loren/./ipsum",
        "loren/../ipsum",
    ],
)
def test_folder_path_normalization_rejects_invalid_public_paths(
    db_session: Session,
    path: str,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")

    with pytest.raises(ValueError, match="folder path"):
        normalize_folder_path(path)
    with pytest.raises(ValueError, match="folder path"):
        resolve_folder_path(db_session, project, path)


def test_create_scan_target_places_named_target_under_folder_with_metadata(
    db_session: Session,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")

    target = create_scan_target(
        db_session,
        project=project,
        folder_path="images/releases",
        name="Production Image",
        target_ref="registry.example.test/app:2026.05",
        metadata_json={"original_image_uri": "registry.example.test/app:latest"},
    )

    assert target.id is not None
    assert target.node_type == AssetNodeType.SCAN_TARGET
    assert target.name == "Production Image"
    assert target.target_ref == "registry.example.test/app:2026.05"
    assert target.metadata_json == {"original_image_uri": "registry.example.test/app:latest"}
    assert target.parent is not None
    assert target.parent.path == "images/releases"
    assert target.path == "images/releases/Production Image"


def test_create_asset_node_allows_valid_targetish_types_and_database_duplicates_raise(
    db_session: Session,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")

    created = create_asset_node(
        db_session,
        project=project,
        parent=None,
        node_type=AssetNodeType.CONTAINER_IMAGE,
        name="app:main",
        target_ref="registry.example.test/app:main",
    )

    assert created.node_type == AssetNodeType.CONTAINER_IMAGE
    assert created.path == "app:main"

    with pytest.raises(IntegrityError):
        create_asset_node(
            db_session,
            project=project,
            parent=None,
            node_type=AssetNodeType.CONTAINER_IMAGE,
            name="app:main",
            target_ref="registry.example.test/app:main-copy",
        )


def test_move_asset_node_updates_node_and_descendant_paths(db_session: Session) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")
    resolve_folder_path(db_session, project, "src")
    api = resolve_folder_path(db_session, project, "src/api")
    target = create_scan_target(
        db_session,
        project=project,
        folder_path="src/api",
        name="service",
        target_ref="repo/service",
    )
    archive = resolve_folder_path(db_session, project, "archive")

    move_asset_node(db_session, api, new_parent=archive)

    assert api.parent is archive
    assert api.path == "archive/api"
    assert target.path == "archive/api/service"
    assert sorted(asset.path for asset in list_project_assets(db_session, project)) == [
        "archive",
        "archive/api",
        "archive/api/service",
        "src",
    ]


def test_move_asset_node_rejects_cycles(db_session: Session) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")
    root = resolve_folder_path(db_session, project, "src")
    child = resolve_folder_path(db_session, project, "src/api")

    with pytest.raises(ValueError, match="cannot move an asset node under itself"):
        move_asset_node(db_session, root, new_parent=root)
    with pytest.raises(ValueError, match="cannot move an asset node under one of its descendants"):
        move_asset_node(db_session, root, new_parent=child)


def test_rename_asset_node_updates_node_and_descendant_paths(db_session: Session) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")
    api = resolve_folder_path(db_session, project, "src/api")
    target = create_scan_target(
        db_session,
        project=project,
        folder_path="src/api",
        name="service",
        target_ref="repo/service",
    )

    rename_asset_node(db_session, api, new_name="backend")

    assert api.name == "backend"
    assert api.path == "src/backend"
    assert target.path == "src/backend/service"


def test_rename_asset_node_keeps_wildcard_like_sibling_paths_unchanged(
    db_session: Session,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")
    wildcard_like = resolve_folder_path(db_session, project, "a_")
    wildcard_child = create_scan_target(
        db_session,
        project=project,
        folder_path="a_",
        name="child",
        target_ref="repo/a-child",
    )
    unrelated = resolve_folder_path(db_session, project, "ab")
    unrelated_child = create_scan_target(
        db_session,
        project=project,
        folder_path="ab",
        name="child",
        target_ref="repo/ab-child",
    )

    rename_asset_node(db_session, wildcard_like, new_name="renamed")

    assert wildcard_child.path == "renamed/child"
    assert unrelated.path == "ab"
    assert unrelated_child.path == "ab/child"


def test_set_asset_sla_overrides_changes_asset_without_project_defaults(
    db_session: Session,
) -> None:
    project = create_project(db_session, slug="alpha", name="Alpha")
    asset = resolve_folder_path(db_session, project, "src")

    updated = set_asset_sla_overrides(
        db_session,
        asset,
        sla_tracking_enabled=False,
        sla_reporting_enabled=False,
    )

    assert updated is asset
    assert asset.sla_tracking_enabled is False
    assert asset.sla_reporting_enabled is False
    assert project.sla_tracking_enabled is True
    assert project.sla_reporting_enabled is True
