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

# cloud_dog_idam — RBAC engine
"""Compute effective roles and permissions."""

from __future__ import annotations

from cloud_dog_idam.rbac.cache import RBACCache


class RBACEngine:
    """Represent r b a c engine."""
    def __init__(
        self,
        *,
        role_permissions: dict[str, set[str]] | None = None,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._user_roles: dict[str, set[str]] = {}
        self._group_memberships: dict[str, set[str]] = {}
        self._group_roles: dict[str, set[str]] = {}
        self._role_permissions = role_permissions or {
            "admin": {"*"},
            "owner": {"users:read", "users:write", "groups:read", "groups:write"},
            "user": {"users:read", "resources:read", "resources:write"},
            "viewer": {"users:read", "resources:read"},
        }
        self._cache = RBACCache(ttl_seconds=cache_ttl_seconds)

    def assign_role_to_user(self, user_id: str, role: str) -> None:
        """Handle assign role to user."""
        self._user_roles.setdefault(user_id, set()).add(role)
        self._cache.invalidate(user_id)

    def add_user_to_group(self, user_id: str, group_id: str) -> None:
        """Handle add user to group."""
        self._group_memberships.setdefault(user_id, set()).add(group_id)
        self._cache.invalidate(user_id)

    def assign_role_to_group(self, group_id: str, role: str) -> None:
        """Handle assign role to group."""
        self._group_roles.setdefault(group_id, set()).add(role)
        for uid, groups in self._group_memberships.items():
            if group_id in groups:
                self._cache.invalidate(uid)

    def get_effective_roles(self, user_id: str) -> set[str]:
        """Return effective roles."""
        cached = self._cache.get(f"roles:{user_id}")
        if cached is not None:
            return cached
        roles = set(self._user_roles.get(user_id, set()))
        for group_id in self._group_memberships.get(user_id, set()):
            roles.update(self._group_roles.get(group_id, set()))
        self._cache.set(f"roles:{user_id}", roles)
        return roles

    def get_effective_permissions(self, user_id: str) -> set[str]:
        """Return effective permissions."""
        cached = self._cache.get(f"perms:{user_id}")
        if cached is not None:
            return cached
        permissions: set[str] = set()
        for role in self.get_effective_roles(user_id):
            permissions.update(self._role_permissions.get(role, set()))
        self._cache.set(f"perms:{user_id}", permissions)
        return permissions

    def has_permission(self, user_id: str, permission: str) -> bool:
        """Return whether this has permission."""
        perms = self.get_effective_permissions(user_id)
        return permission in perms or "*" in perms

    def authorise(self, user_id: str, resource: str, action: str) -> bool:
        """Handle authorise."""
        return self.has_permission(user_id, f"{resource}:{action}")
