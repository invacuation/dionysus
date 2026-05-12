"""Project inventory creation and lookup services."""

import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from dionysus.models.inventory import Project

_WHITESPACE_RE = re.compile(r"\s")


def create_project(
    session: Session,
    *,
    slug: str,
    name: str,
    description: str | None = None,
    sla_tracking_enabled: bool = True,
    sla_reporting_enabled: bool = True,
    require_peer_review_for_status_changes: bool = False,
    grace_period_enabled: bool = False,
    grace_period_percent: int = 100,
) -> Project:
    """Create and flush a project inventory root.

    Args:
        session: The database session used to persist the project.
        slug: The unique URL/API-safe project slug.
        name: The human-readable project name.
        description: Optional operator-facing project description.
        sla_tracking_enabled: Default SLA tracking setting for the project.
        sla_reporting_enabled: Default SLA reporting setting for the project.
        require_peer_review_for_status_changes: Whether project finding status
            changes require peer-review approval before applying.
        grace_period_enabled: Whether grace-period calculations are enabled.
        grace_period_percent: Positive grace-period percentage.

    Returns:
        The flushed project model.

    Raises:
        ValueError: If the slug, name, or grace percentage is invalid.
    """

    validated_slug = _validate_slug(slug)
    validated_name = _validate_name(name)
    if grace_period_percent <= 0:
        raise ValueError("grace period percent must be positive")

    project = Project(
        slug=validated_slug,
        name=validated_name,
        description=description,
        sla_tracking_enabled=sla_tracking_enabled,
        sla_reporting_enabled=sla_reporting_enabled,
        require_peer_review_for_status_changes=require_peer_review_for_status_changes,
        grace_period_enabled=grace_period_enabled,
        grace_period_percent=grace_period_percent,
    )
    session.add(project)
    session.flush()
    return project


def update_project(
    session: Session,
    project: Project,
    *,
    slug: str | None = None,
    name: str | None = None,
) -> Project:
    """Update mutable project identity fields and flush the project.

    Args:
        session: The database session used to persist the project.
        project: The project to mutate.
        slug: Optional replacement project slug.
        name: Optional replacement human-readable project name.

    Returns:
        The flushed project model.

    Raises:
        ValueError: If the slug or name is invalid or already used by another project.
    """

    if slug is not None:
        validated_slug = _validate_slug(slug)
        _ensure_unique_project_identity(session, project, slug=validated_slug)
        project.slug = validated_slug
    if name is not None:
        validated_name = _validate_name(name)
        _ensure_unique_project_identity(session, project, name=validated_name)
        project.name = validated_name
    session.flush()
    return project


def get_project_by_slug(session: Session, slug: str) -> Project | None:
    """Return a project by slug.

    Args:
        session: The database session used for lookup.
        slug: The project slug to find.

    Returns:
        The matching project, or ``None`` when it does not exist.
    """

    return session.scalar(select(Project).where(Project.slug == slug))


def get_project(session: Session, project_id: str) -> Project | None:
    """Return a project by identifier.

    Args:
        session: The database session used for lookup.
        project_id: The project UUID string to find.

    Returns:
        The matching project, or ``None`` when it does not exist.
    """

    return session.get(Project, project_id)


def list_projects(session: Session) -> list[Project]:
    """Return projects sorted deterministically by name, then slug.

    Args:
        session: The database session used for lookup.

    Returns:
        All projects ordered by ``name`` and then ``slug`` for stable UI/API output.
    """

    return list(session.scalars(select(Project).order_by(Project.name, Project.slug)))


def delete_project(session: Session, project: Project) -> None:
    """Delete a project and its ORM-cascaded inventory dependents.

    Args:
        session: The database session used to delete the project.
        project: The project to remove.
    """

    session.delete(project)
    session.flush()


def _validate_slug(slug: str) -> str:
    if not slug:
        raise ValueError("project slug must be non-empty")
    if _WHITESPACE_RE.search(slug):
        raise ValueError("project slug must not contain whitespace")
    return slug


def _validate_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise ValueError("project name must be non-empty")
    return normalized


def _ensure_unique_project_identity(
    session: Session,
    project: Project,
    *,
    slug: str | None = None,
    name: str | None = None,
) -> None:
    conflict_filters = []
    if slug is not None and slug != project.slug:
        conflict_filters.append(Project.slug == slug)
    if name is not None and name != project.name:
        conflict_filters.append(Project.name == name)
    if not conflict_filters:
        return

    conflict = session.scalar(
        select(Project).where(Project.id != project.id).where(or_(*conflict_filters))
    )
    if conflict is not None:
        raise ValueError("project slug or name already exists")
