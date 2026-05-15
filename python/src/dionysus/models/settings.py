"""Application security settings persistence models."""

from sqlalchemy import Boolean, CheckConstraint, Integer, String, false
from sqlalchemy.orm import Mapped, mapped_column

from dionysus.models.base import Base, TimestampMixin


class AppSecuritySettings(TimestampMixin, Base):
    """Singleton application-wide security settings.

    Attributes:
        id: Stable singleton row identifier.
        force_peer_review_for_status_changes: Whether every finding status
            transition must enter peer review before it can be applied.
    """

    __tablename__ = "app_security_settings"
    __table_args__ = (
        CheckConstraint(
            "session_idle_timeout_minutes IS NULL OR session_idle_timeout_minutes > 0",
            name="ck_app_security_settings_session_idle_timeout_positive",
        ),
        CheckConstraint(
            "session_absolute_timeout_minutes IS NULL OR session_absolute_timeout_minutes > 0",
            name="ck_app_security_settings_session_absolute_timeout_positive",
        ),
        CheckConstraint(
            "session_idle_timeout_minutes IS NULL "
            "OR session_absolute_timeout_minutes IS NULL "
            "OR session_absolute_timeout_minutes >= session_idle_timeout_minutes",
            name="ck_app_security_settings_session_absolute_timeout_gte_idle",
        ),
    )

    id: Mapped[str] = mapped_column(String(50), primary_key=True, default="default")
    force_peer_review_for_status_changes: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=false(),
        nullable=False,
    )
    session_idle_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    session_absolute_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
