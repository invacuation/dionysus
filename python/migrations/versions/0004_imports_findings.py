"""imports and findings tables

Revision ID: 0004_imports_findings
Revises: 0003_project_asset_inventory
Create Date: 2026-05-07 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_imports_findings"
down_revision: str | None = "0003_project_asset_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create import attempt, scan, raw finding, and vulnerability group tables.

    Returns:
        None.
    """

    op.create_table(
        "import_attempts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("asset_node_id", sa.String(), nullable=True),
        sa.Column("uploader_principal_type", sa.String(length=50), nullable=True),
        sa.Column("uploader_principal_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("parser_name", sa.String(length=120), nullable=False),
        sa.Column("sanitized_message", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(length=120), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status in ('pending', 'success', 'failed')",
            name=op.f("ck_import_attempts_status"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_node_id"],
            ["asset_nodes.id"],
            name=op.f("fk_import_attempts_asset_node_id_asset_nodes"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_import_attempts_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_import_attempts")),
    )
    op.create_index(
        "ix_import_attempts_asset_node_status",
        "import_attempts",
        ["asset_node_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_import_attempts_asset_node_id"),
        "import_attempts",
        ["asset_node_id"],
        unique=False,
    )
    op.create_index(
        "ix_import_attempts_correlation_id",
        "import_attempts",
        ["correlation_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_import_attempts_parser_name"),
        "import_attempts",
        ["parser_name"],
        unique=False,
    )
    op.create_index(
        "ix_import_attempts_project_status",
        "import_attempts",
        ["project_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_import_attempts_project_id"),
        "import_attempts",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_import_attempts_status"),
        "import_attempts",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_import_attempts_uploader_principal_id"),
        "import_attempts",
        ["uploader_principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_import_attempts_uploader_principal_type"),
        "import_attempts",
        ["uploader_principal_type"],
        unique=False,
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_target_id", sa.String(), nullable=False),
        sa.Column("scanner_kind", sa.String(length=50), nullable=False),
        sa.Column("report_kind", sa.String(length=120), nullable=False),
        sa.Column("parser_version", sa.String(length=50), nullable=False),
        sa.Column("scan_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "scanner_kind in ('trivy')",
            name=op.f("ck_scans_scanner_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_scans_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_target_id"],
            ["asset_nodes.id"],
            name=op.f("fk_scans_scan_target_id_asset_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
    )
    op.create_index(op.f("ix_scans_project_id"), "scans", ["project_id"], unique=False)
    op.create_index(
        "ix_scans_project_target",
        "scans",
        ["project_id", "scan_target_id"],
        unique=False,
    )
    op.create_index(op.f("ix_scans_report_kind"), "scans", ["report_kind"], unique=False)
    op.create_index(
        "ix_scans_scanner_kind",
        "scans",
        ["scanner_kind"],
        unique=False,
    )
    op.create_index(op.f("ix_scans_scan_target_id"), "scans", ["scan_target_id"], unique=False)

    op.create_table(
        "project_vulnerability_groups",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("primary_identifier", sa.String(length=255), nullable=False),
        sa.Column("additional_identifiers_json", sa.JSON(), nullable=False),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("dedupe_key", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name=op.f("ck_project_vulnerability_groups_status"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_project_vulnerability_groups_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_project_vulnerability_groups")),
        sa.UniqueConstraint(
            "project_id",
            "dedupe_key",
            name=op.f("uq_project_vulnerability_groups_project_dedupe_key"),
        ),
    )
    op.create_index(
        op.f("ix_project_vulnerability_groups_primary_identifier"),
        "project_vulnerability_groups",
        ["primary_identifier"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_vulnerability_groups_project_id"),
        "project_vulnerability_groups",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_project_vulnerability_groups_project_status",
        "project_vulnerability_groups",
        ["project_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_vulnerability_groups_severity"),
        "project_vulnerability_groups",
        ["severity"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_vulnerability_groups_status"),
        "project_vulnerability_groups",
        ["status"],
        unique=False,
    )

    op.create_table(
        "raw_finding_instances",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("scan_target_id", sa.String(), nullable=False),
        sa.Column("scanner_kind", sa.String(length=50), nullable=False),
        sa.Column("scanner_finding_id", sa.Text(), nullable=False),
        sa.Column("dedupe_key", sa.String(length=512), nullable=False),
        sa.Column("identifiers_json", sa.JSON(), nullable=False),
        sa.Column("primary_identifier", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("cvss_json", sa.JSON(), nullable=False),
        sa.Column("package_name", sa.String(length=255), nullable=True),
        sa.Column("package_version", sa.String(length=255), nullable=True),
        sa.Column("fixed_version", sa.String(length=255), nullable=True),
        sa.Column("artifact_name", sa.Text(), nullable=True),
        sa.Column("artifact_type", sa.String(length=120), nullable=True),
        sa.Column("artifact_path", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("present_in_latest_scan", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("source_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "scanner_kind in ('trivy')",
            name=op.f("ck_raw_finding_instances_scanner_kind"),
        ),
        sa.CheckConstraint(
            "status in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name=op.f("ck_raw_finding_instances_status"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_raw_finding_instances_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_raw_finding_instances_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_target_id"],
            ["asset_nodes.id"],
            name=op.f("fk_raw_finding_instances_scan_target_id_asset_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_finding_instances")),
        sa.UniqueConstraint(
            "scan_target_id",
            "dedupe_key",
            name=op.f("uq_raw_finding_instances_scan_target_dedupe_key"),
        ),
    )
    op.create_index(
        op.f("ix_raw_finding_instances_artifact_type"),
        "raw_finding_instances",
        ["artifact_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_package_name"),
        "raw_finding_instances",
        ["package_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_present_in_latest_scan"),
        "raw_finding_instances",
        ["present_in_latest_scan"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_primary_identifier"),
        "raw_finding_instances",
        ["primary_identifier"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_project_id"),
        "raw_finding_instances",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_raw_finding_instances_project_status",
        "raw_finding_instances",
        ["project_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_scan_id"),
        "raw_finding_instances",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_raw_finding_instances_scan_status",
        "raw_finding_instances",
        ["scan_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_scan_target_id"),
        "raw_finding_instances",
        ["scan_target_id"],
        unique=False,
    )
    op.create_index(
        "ix_raw_finding_instances_latest",
        "raw_finding_instances",
        ["scan_target_id", "present_in_latest_scan"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_scanner_kind"),
        "raw_finding_instances",
        ["scanner_kind"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_severity"),
        "raw_finding_instances",
        ["severity"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_finding_instances_status"),
        "raw_finding_instances",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    """Drop import attempt, scan, raw finding, and vulnerability group tables.

    Returns:
        None.
    """

    op.drop_index(op.f("ix_raw_finding_instances_status"), table_name="raw_finding_instances")
    op.drop_index(op.f("ix_raw_finding_instances_severity"), table_name="raw_finding_instances")
    op.drop_index(
        op.f("ix_raw_finding_instances_scanner_kind"),
        table_name="raw_finding_instances",
    )
    op.drop_index("ix_raw_finding_instances_latest", table_name="raw_finding_instances")
    op.drop_index(
        op.f("ix_raw_finding_instances_scan_target_id"),
        table_name="raw_finding_instances",
    )
    op.drop_index("ix_raw_finding_instances_scan_status", table_name="raw_finding_instances")
    op.drop_index(op.f("ix_raw_finding_instances_scan_id"), table_name="raw_finding_instances")
    op.drop_index("ix_raw_finding_instances_project_status", table_name="raw_finding_instances")
    op.drop_index(
        op.f("ix_raw_finding_instances_project_id"),
        table_name="raw_finding_instances",
    )
    op.drop_index(
        op.f("ix_raw_finding_instances_primary_identifier"),
        table_name="raw_finding_instances",
    )
    op.drop_index(
        op.f("ix_raw_finding_instances_present_in_latest_scan"),
        table_name="raw_finding_instances",
    )
    op.drop_index(
        op.f("ix_raw_finding_instances_package_name"),
        table_name="raw_finding_instances",
    )
    op.drop_index(
        op.f("ix_raw_finding_instances_artifact_type"),
        table_name="raw_finding_instances",
    )
    op.drop_table("raw_finding_instances")

    op.drop_index(
        op.f("ix_project_vulnerability_groups_status"),
        table_name="project_vulnerability_groups",
    )
    op.drop_index(
        op.f("ix_project_vulnerability_groups_severity"),
        table_name="project_vulnerability_groups",
    )
    op.drop_index(
        "ix_project_vulnerability_groups_project_status",
        table_name="project_vulnerability_groups",
    )
    op.drop_index(
        op.f("ix_project_vulnerability_groups_project_id"),
        table_name="project_vulnerability_groups",
    )
    op.drop_index(
        op.f("ix_project_vulnerability_groups_primary_identifier"),
        table_name="project_vulnerability_groups",
    )
    op.drop_table("project_vulnerability_groups")

    op.drop_index(op.f("ix_scans_scan_target_id"), table_name="scans")
    op.drop_index("ix_scans_scanner_kind", table_name="scans")
    op.drop_index(op.f("ix_scans_report_kind"), table_name="scans")
    op.drop_index("ix_scans_project_target", table_name="scans")
    op.drop_index(op.f("ix_scans_project_id"), table_name="scans")
    op.drop_table("scans")

    op.drop_index(
        op.f("ix_import_attempts_uploader_principal_type"),
        table_name="import_attempts",
    )
    op.drop_index(
        op.f("ix_import_attempts_uploader_principal_id"),
        table_name="import_attempts",
    )
    op.drop_index(op.f("ix_import_attempts_status"), table_name="import_attempts")
    op.drop_index(op.f("ix_import_attempts_project_id"), table_name="import_attempts")
    op.drop_index("ix_import_attempts_project_status", table_name="import_attempts")
    op.drop_index(op.f("ix_import_attempts_parser_name"), table_name="import_attempts")
    op.drop_index("ix_import_attempts_correlation_id", table_name="import_attempts")
    op.drop_index(op.f("ix_import_attempts_asset_node_id"), table_name="import_attempts")
    op.drop_index("ix_import_attempts_asset_node_status", table_name="import_attempts")
    op.drop_table("import_attempts")
