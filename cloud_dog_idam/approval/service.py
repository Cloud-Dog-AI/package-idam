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

# cloud_dog_idam — Approval workflow service
"""Approval workflow handling for pending user activation and rejection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cloud_dog_idam.domain.enums import UserStatus
from cloud_dog_idam.domain.models import User


@dataclass(slots=True)
class ApprovalRecord:
    """Represent approval record."""
    user_id: str
    approver_id: str
    action: str
    reason: str
    timestamp: datetime


class ApprovalService:
    """Represent approval service."""
    def __init__(self, *, approval_ttl_seconds: int = 86_400) -> None:
        self._history: list[ApprovalRecord] = []
        self._pending_since: dict[str, datetime] = {}
        self._ttl = approval_ttl_seconds

    def mark_pending(self, user: User) -> User:
        """Mark pending."""
        user.status = UserStatus.PENDING_APPROVAL
        self._pending_since[user.user_id] = datetime.now(timezone.utc)
        return user

    def approve(
        self, user: User, *, approver_id: str = "system", role: str = "user"
    ) -> User:
        """Handle approve."""
        user.status = UserStatus.ACTIVE
        user.role = role
        self._pending_since.pop(user.user_id, None)
        self._history.append(
            ApprovalRecord(
                user.user_id, approver_id, "approve", "", datetime.now(timezone.utc)
            )
        )
        return user

    def reject(self, user: User, *, approver_id: str, reason: str) -> User:
        """Handle reject."""
        user.status = UserStatus.DISABLED
        self._pending_since.pop(user.user_id, None)
        self._history.append(
            ApprovalRecord(
                user.user_id, approver_id, "reject", reason, datetime.now(timezone.utc)
            )
        )
        return user

    def get_pending_approvals(self, users: list[User]) -> list[User]:
        """Return pending approvals."""
        return [u for u in users if u.status == UserStatus.PENDING_APPROVAL]

    def get_approval_history(self, user_id: str) -> list[ApprovalRecord]:
        """Return approval history."""
        return [r for r in self._history if r.user_id == user_id]

    def expire_pending(self, users: list[User]) -> int:
        """Handle expire pending."""
        now = datetime.now(timezone.utc)
        expired = 0
        for user in users:
            if user.status != UserStatus.PENDING_APPROVAL:
                continue
            since = self._pending_since.get(user.user_id)
            if since and now - since > timedelta(seconds=self._ttl):
                user.status = UserStatus.DISABLED
                expired += 1
        return expired
