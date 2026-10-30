"""Add is_verified to users and create revoked_tokens table

Revision ID: e1a34b678901
Revises: d2575a9c427f
Create Date: 2026-10-16 21:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1a34b678901'
down_revision: Union[str, Sequence[str], None] = 'd2575a9c427f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('is_verified', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.create_table(
        'revoked_tokens',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('jti', sa.String(length=64), nullable=False),
        sa.Column('token_type', sa.String(length=32), nullable=True, server_default='access'),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_revoked_tokens_id', 'revoked_tokens', ['id'], unique=False)
    op.create_index('ix_revoked_tokens_jti', 'revoked_tokens', ['jti'], unique=True)


def downgrade() -> None:
    op.drop_index('ix_revoked_tokens_jti', table_name='revoked_tokens')
    op.drop_index('ix_revoked_tokens_id', table_name='revoked_tokens')
    op.drop_table('revoked_tokens')
    op.drop_column('users', 'is_verified')
