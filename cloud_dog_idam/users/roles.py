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

# cloud_dog_idam — Role service
"""Role CRUD and assignment operations with optional repository backing."""

from __future__ import annotations

from typing import Protocol

from cloud_dog_idam.domain.models import Role


class RoleRepository(Protocol):
    """Represent role repository."""

    def save(self, role: Role) -> Role:
        """Persist a role."""
        ...

    def list_all(self) -> list[Role]:
        """List all roles."""
        ...

    def assign(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user."""
        ...

    def assigned(self, user_id: str) -> set[str]:
        """Return assigned role names for a user."""
        ...


class RoleService:
    """Provide role CRUD and assignment operations."""
    def __init__(self, repository: RoleRepository | None = None) -> None:
        self._repo = repository
        self._roles: dict[str, Role] = {}
        self._assignments: dict[str, set[str]] = {}

    def create(self, role: Role) -> Role:
        """Create a role."""
        if self._repo is not None:
            return self._repo.save(role)
        self._roles[role.role_id] = role
        return role

    def assign(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user."""
        if self._repo is not None and hasattr(self._repo, "assign"):
            self._repo.assign(user_id, role_name)
            return
        self._assignments.setdefault(user_id, set()).add(role_name)

    def get_assigned(self, user_id: str) -> set[str]:
        """Return assigned role names for a user."""
        if self._repo is not None and hasattr(self._repo, "assigned"):
            return set(self._repo.assigned(user_id))
        return set(self._assignments.get(user_id, set()))

    def list(self) -> list[Role]:
        """List available roles."""
        if self._repo is not None and hasattr(self._repo, "list_all"):
            return self._repo.list_all()
        return list(self._roles.values())
