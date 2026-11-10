"""Add updated_at to users.

Revision ID: f2b4c6d8e0a1
Revises: e1a34b678901
Create Date: 2026-10-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f2b4c6d8e0a1"
down_revision: Union[str, Sequence[str], None] = "e1a34b678901"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "updated_at")
