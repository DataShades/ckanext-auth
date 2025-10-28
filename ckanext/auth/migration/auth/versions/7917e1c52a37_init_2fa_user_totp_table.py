"""Init 2fa_user_totp table.

Revision ID: 7917e1c52a37
Revises:
Create Date: 2024-08-01 15:38:57.177385

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "7917e1c52a37"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "2fa_user_secret",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("last_access", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", "user_id"),
    )


def downgrade():
    op.drop_table("2fa_user_secret")
