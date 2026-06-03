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

# cloud_dog_idam — Provisioning policies
"""Manual/JIT/Sync provisioning logic with deprovision support."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dog_idam.domain.enums import ProvisioningMode, UserStatus
from cloud_dog_idam.domain.models import User


@dataclass(slots=True)
class SyncResult:
    """Represent sync result."""
    created: int = 0
    updated: int = 0
    disabled: int = 0


class ProvisioningService:
    """Provisioning service for manual/JIT/sync modes."""

    def provision_user(
        self,
        *,
        mode: ProvisioningMode,
        username: str,
        email: str,
        default_role: str = "viewer",
        mapped_roles: list[str] | None = None,
    ) -> User:
        """Handle provision user."""
        if mode == ProvisioningMode.MANUAL:
            status = UserStatus.PENDING_APPROVAL
        else:
            status = UserStatus.ACTIVE
        role = mapped_roles[0] if mapped_roles else default_role
        return User(username=username, email=email, role=role, status=status)

    def sync_from_directory(
        self, existing_users: dict[str, User], directory_users: list[dict]
    ) -> SyncResult:
        """Handle sync from directory."""
        result = SyncResult()
        seen_emails: set[str] = set()
        for item in directory_users:
            email = str(item.get("email", "")).lower()
            if not email:
                continue
            seen_emails.add(email)
            username = str(item.get("username", email.split("@")[0]))
            role = str(item.get("role", "viewer"))
            if email not in existing_users:
                existing_users[email] = User(
                    username=username, email=email, role=role, status=UserStatus.ACTIVE
                )
                result.created += 1
                continue
            user = existing_users[email]
            changed = False
            if user.username != username:
                user.username = username
                changed = True
            if user.role != role:
                user.role = role
                changed = True
            if user.status != UserStatus.ACTIVE:
                user.status = UserStatus.ACTIVE
                changed = True
            if changed:
                result.updated += 1

        for email, user in existing_users.items():
            if email not in seen_emails and user.status != UserStatus.DISABLED:
                user.status = UserStatus.DISABLED
                result.disabled += 1
        return result

    def deprovision_user(self, user: User) -> User:
        """Handle deprovision user."""
        user.status = UserStatus.DISABLED
        return user


def provision_user(
    *, mode: ProvisioningMode, username: str, email: str, default_role: str = "viewer"
) -> User:
    """Handle provision user."""
    return ProvisioningService().provision_user(
        mode=mode,
        username=username,
        email=email,
        default_role=default_role,
    )
