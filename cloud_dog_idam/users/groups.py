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

# cloud_dog_idam — Group service
"""Group CRUD and membership operations with optional repository backing."""

from __future__ import annotations

from typing import Protocol

from cloud_dog_idam.domain.models import Group


class GroupRepository(Protocol):
    """Represent group repository."""

    def save(self, group: Group) -> Group:
        """Persist a group."""
        ...

    def list_all(self) -> list[Group]:
        """List all groups."""
        ...

    def add_member(self, group_id: str, user_id: str) -> None:
        """Add a user to a group."""
        ...

    def members(self, group_id: str) -> set[str]:
        """Return members for a group."""
        ...


class GroupService:
    """Provide group CRUD and membership operations."""
    def __init__(self, repository: GroupRepository | None = None) -> None:
        self._repo = repository
        self._groups: dict[str, Group] = {}
        self._members: dict[str, set[str]] = {}

    def create(self, group: Group) -> Group:
        """Create a group."""
        if self._repo is not None:
            return self._repo.save(group)
        self._groups[group.group_id] = group
        self._members.setdefault(group.group_id, set())
        return group

    def add_member(self, group_id: str, user_id: str) -> None:
        """Add a user to a group."""
        if self._repo is not None and hasattr(self._repo, "add_member"):
            self._repo.add_member(group_id, user_id)
            return
        self._members.setdefault(group_id, set()).add(user_id)

    def members(self, group_id: str) -> set[str]:
        """Return members for a group."""
        if self._repo is not None and hasattr(self._repo, "members"):
            return set(self._repo.members(group_id))
        return set(self._members.get(group_id, set()))

    def list(self) -> list[Group]:
        """List groups from the backing store."""
        if self._repo is not None and hasattr(self._repo, "list_all"):
            return self._repo.list_all()
        return list(self._groups.values())
