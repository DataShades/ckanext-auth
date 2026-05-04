"""Add auth_passkey table

Revision ID: 645822b5db95
Revises: 7917e1c52a37
Create Date: 2026-05-04 09:08:55.482207

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '645822b5db95'
down_revision = '7917e1c52a37'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "auth_passkey",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("name", sa.Text(), nullable=False, server_default=""),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )


def downgrade():
    op.drop_table("auth_passkey")
