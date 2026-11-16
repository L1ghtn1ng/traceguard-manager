"""triage history, muting, notifications, account security

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-16 08:09:43.163483
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "mute_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=200), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("mute_rules", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_mute_rules_rule_id"), ["rule_id"], unique=False)

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=True),
        sa.Column("min_level", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=300), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "alert_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=True),
        sa.Column("assignee", sa.String(length=64), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("alert_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_alert_events_alert_id"), ["alert_id"], unique=False)

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "tags",
                sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
                server_default="[]",
                nullable=False,
            )
        )

    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("assignee_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(batch_op.f("ix_alerts_assignee_id"), ["assignee_id"], unique=False)
        batch_op.create_foreign_key("fk_alerts_assignee_id_users", "users", ["assignee_id"], ["id"], ondelete="SET NULL")

    with op.batch_alter_table("user_sessions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("user_agent", sa.String(length=200), nullable=True))

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("must_change_password", sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column("totp_secret", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("totp_last_step", sa.BigInteger(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "recovery_codes",
                sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
                server_default="[]",
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("recovery_codes")
        batch_op.drop_column("totp_last_step")
        batch_op.drop_column("totp_enabled_at")
        batch_op.drop_column("totp_secret")
        batch_op.drop_column("must_change_password")

    with op.batch_alter_table("user_sessions", schema=None) as batch_op:
        batch_op.drop_column("user_agent")

    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.drop_constraint("fk_alerts_assignee_id_users", type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_alerts_assignee_id"))
        batch_op.drop_column("notified_at")
        batch_op.drop_column("assignee_id")

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("tags")

    with op.batch_alter_table("alert_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_alert_events_alert_id"))

    op.drop_table("alert_events")
    op.drop_table("notification_channels")
    with op.batch_alter_table("mute_rules", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_mute_rules_rule_id"))

    op.drop_table("mute_rules")
