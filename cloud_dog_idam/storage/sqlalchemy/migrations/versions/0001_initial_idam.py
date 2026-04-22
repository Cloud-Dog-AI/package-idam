# Copyright 2026 Cloud-Dog, Viewdeck Engineering Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# cloud_dog_idam — Alembic initial migration
"""Create baseline IDAM tables.

Revision ID: 0001_initial_idam
Revises:
Create Date: 2026-02-17
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_idam"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Handle upgrade."""
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(length=64), primary_key=True),
        sa.Column("username", sa.String(length=128), nullable=False, unique=True),
        sa.Column("email", sa.String(length=256), nullable=False, unique=True),
        sa.Column(
            "display_name", sa.String(length=256), nullable=False, server_default=""
        ),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="active"
        ),
        sa.Column(
            "role", sa.String(length=64), nullable=False, server_default="viewer"
        ),
        sa.Column(
            "is_system_user", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
    )

    op.create_table(
        "api_keys",
        sa.Column("api_key_id", sa.String(length=64), primary_key=True),
        sa.Column(
            "owner_user_id",
            sa.String(length=64),
            sa.ForeignKey("users.user_id"),
            nullable=False,
        ),
        sa.Column("key_hash", sa.Text(), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="active"
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Handle downgrade."""
    op.drop_table("api_keys")
    op.drop_table("users")
