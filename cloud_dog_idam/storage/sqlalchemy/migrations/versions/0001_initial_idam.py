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
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column(
            "display_name", sa.String(length=256), nullable=False, server_default=""
        ),
        sa.Column("password_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="active"
        ),
        sa.Column("role", sa.String(length=64), nullable=False, server_default="user"),
        sa.Column(
            "is_system_user", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "username", name="uq_users_tenant_username"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "identities",
        sa.Column("identity_id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("provider_type", sa.String(length=32), nullable=False),
        sa.Column("provider_id", sa.String(length=128), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_identities_user_id", "identities", ["user_id"])

    op.create_table(
        "groups",
        sa.Column("group_id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "roles",
        sa.Column("role_id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "group_memberships",
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("users.user_id"), primary_key=True),
        sa.Column("group_id", sa.String(length=64), sa.ForeignKey("groups.group_id"), primary_key=True),
        sa.Column("role_in_group", sa.String(length=64), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("users.user_id"), primary_key=True),
        sa.Column("role_id", sa.String(length=64), sa.ForeignKey("roles.role_id"), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "group_roles",
        sa.Column("group_id", sa.String(length=64), sa.ForeignKey("groups.group_id"), primary_key=True),
        sa.Column("role_id", sa.String(length=64), sa.ForeignKey("roles.role_id"), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "permissions",
        sa.Column("permission_id", sa.String(length=64), primary_key=True),
        sa.Column("resource", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
    )

    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.String(length=64), sa.ForeignKey("roles.role_id"), primary_key=True),
        sa.Column("permission_id", sa.String(length=64), sa.ForeignKey("permissions.permission_id"), primary_key=True),
    )

    op.create_table(
        "resource_types",
        sa.Column("resource_type_id", sa.String(length=64), primary_key=True),
        sa.Column("project", sa.String(length=128), nullable=False),
        sa.Column("type", sa.String(length=128), nullable=False),
        sa.Column("label", sa.String(length=256), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=True),
        sa.Column("list_endpoint", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_resource_types_project", "resource_types", ["project"])

    op.create_table(
        "resource_instances",
        sa.Column("resource_instance_id", sa.String(length=64), primary_key=True),
        sa.Column("project", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column("resource_id", sa.String(length=256), nullable=False),
        sa.Column("label", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_resource_instances_project", "resource_instances", ["project"])

    op.create_table(
        "rbac_bindings",
        sa.Column("binding_id", sa.String(length=64), primary_key=True),
        sa.Column("subject_type", sa.String(length=16), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("project", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column("resource_id", sa.String(length=256), nullable=False, server_default="*"),
        sa.Column("permission", sa.String(length=128), nullable=False),
        sa.Column("granted_by", sa.String(length=64), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_rbac_bindings_subject_id", "rbac_bindings", ["subject_id"])
    op.create_index("ix_rbac_bindings_project", "rbac_bindings", ["project"])

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
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_owner_user_id", "api_keys", ["owner_user_id"])

    op.create_table(
        "refresh_tokens",
        sa.Column("token_id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])

    op.create_table(
        "sessions",
        sa.Column("session_id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    op.create_table(
        "policies",
        sa.Column("policy_id", sa.String(length=64), primary_key=True),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False, server_default="user"),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False, server_default="success"),
        sa.Column("correlation_id", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("service", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("details", sa.JSON(), nullable=True),
    )
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])
    op.create_index("ix_audit_events_correlation_id", "audit_events", ["correlation_id"])


def downgrade() -> None:
    """Handle downgrade."""
    op.drop_table("audit_events")
    op.drop_table("policies")
    op.drop_table("sessions")
    op.drop_table("refresh_tokens")
    op.drop_table("api_keys")
    op.drop_table("rbac_bindings")
    op.drop_table("resource_instances")
    op.drop_table("resource_types")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("group_roles")
    op.drop_table("user_roles")
    op.drop_table("group_memberships")
    op.drop_table("roles")
    op.drop_table("groups")
    op.drop_table("identities")
    op.drop_table("users")
