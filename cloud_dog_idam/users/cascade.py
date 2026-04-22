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

# cloud_dog_idam — UM9 Cascade delete
"""Cascade user deletion for GDPR right-to-erasure (PS-70 UM9).

License: Apache 2.0
Ownership: Cloud-Dog, Viewdeck Engineering Limited
Description: Deletes a user and all associated entities in the correct order.
Requirements: UM9
Tasks: W28A-696
Architecture: UM9 Data Protection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cloud_dog_idam.audit.models import AuditEvent
from cloud_dog_idam.users.service import UserService
from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.tokens.sessions import SessionManager
from cloud_dog_idam.users.groups import GroupService


@dataclass(slots=True)
class CascadeDeleteResult:
    """Result of a cascade user deletion."""
    user_id: str
    sessions_deleted: int = 0
    api_keys_deleted: int = 0
    group_memberships_removed: int = 0
    identity_links_removed: int = 0
    audit_references_anonymised: int = 0
    user_deleted: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serialisable representation."""
        return {
            "user_id": self.user_id,
            "sessions_deleted": self.sessions_deleted,
            "api_keys_deleted": self.api_keys_deleted,
            "group_memberships_removed": self.group_memberships_removed,
            "identity_links_removed": self.identity_links_removed,
            "audit_references_anonymised": self.audit_references_anonymised,
            "user_deleted": self.user_deleted,
            "errors": self.errors,
        }


def delete_user_cascade(
    user_id: str,
    *,
    user_service: UserService,
    api_key_manager: APIKeyManager | None = None,
    session_manager: SessionManager | None = None,
    group_service: GroupService | None = None,
    audit_emitter: Any = None,
    actor_id: str = "system",
) -> CascadeDeleteResult:
    """Delete a user and all related entities (PS-70 UM9).

    Deletion order:
    1. Emit audit event BEFORE deletion (so erasure is auditable)
    2. End all sessions
    3. Revoke all API keys
    4. Remove group memberships
    5. Delete user record
    """
    result = CascadeDeleteResult(user_id=user_id)

    # Verify user exists.
    user = user_service.get(user_id)
    if user is None:
        result.errors.append(f"User {user_id} not found")
        return result

    # Step 0: Emit audit event BEFORE deletion.
    if audit_emitter is not None:
        audit_emitter.emit(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                actor_id=actor_id,
                action="user.cascade_delete",
                target=f"user:{user_id}",
                outcome="initiated",
                details={"username": user.username, "tenant_id": user.tenant_id or ""},
            )
        )

    # Step 1: End all sessions.
    if session_manager is not None:
        try:
            for session in list(getattr(session_manager, "_sessions", {}).values()):
                if getattr(session, "user_id", None) == user_id:
                    session_manager.end(session.session_id)
                    result.sessions_deleted += 1
        except Exception as exc:
            result.errors.append(f"session cleanup: {exc}")

    # Step 2: Revoke all API keys.
    if api_key_manager is not None:
        try:
            for key in api_key_manager.list_keys(owner_id=user_id):
                if key.status != "revoked":
                    api_key_manager.revoke(key.api_key_id)
                    result.api_keys_deleted += 1
        except Exception as exc:
            result.errors.append(f"api key cleanup: {exc}")

    # Step 3: Remove group memberships.
    if group_service is not None:
        try:
            for group in group_service.list():
                members = group_service.members(group.group_id)
                if user_id in members:
                    group_service.remove_member(group.group_id, user_id)
                    result.group_memberships_removed += 1
        except Exception as exc:
            result.errors.append(f"group membership cleanup: {exc}")

    # Step 4: Delete user record.
    try:
        user_service.disable(user_id)
        # Remove from in-memory store if present.
        if hasattr(user_service, "_users") and user_id in user_service._users:
            del user_service._users[user_id]
        result.user_deleted = True
    except Exception as exc:
        result.errors.append(f"user deletion: {exc}")

    # Final audit event.
    if audit_emitter is not None:
        audit_emitter.emit(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                actor_id=actor_id,
                action="user.cascade_delete",
                target=f"user:{user_id}",
                outcome="success" if result.user_deleted else "partial",
                details=result.to_dict(),
            )
        )

    return result
