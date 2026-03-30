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

# cloud_dog_idam — User service
"""User CRUD and search operations with optional repository backing."""

from __future__ import annotations

from typing import Protocol

from cloud_dog_idam.domain.models import User


class UserRepository(Protocol):
    """Repository interface for user persistence."""

    def save(self, user: User) -> User:
        """Persist a user record."""
        ...

    def get(self, user_id: str) -> User | None:
        """Return a user by identifier."""
        ...

    def update(self, user_id: str, changes: dict[str, object]) -> User:
        """Update a user with the supplied changes."""
        ...

    def search(self, term: str) -> list[User]:
        """Search for users matching the term."""
        ...

    def list_all(self) -> list[User]:
        """List all users from the repository."""
        ...


class UserService:
    """Provide user CRUD and search operations."""
    def __init__(self, repository: UserRepository | None = None) -> None:
        self._repo = repository
        self._users: dict[str, User] = {}

    def _repo_get(self, user_id: str) -> User | None:
        if self._repo is None:
            return None
        if hasattr(self._repo, "get"):
            return self._repo.get(user_id)  # type: ignore[call-arg]
        if hasattr(self._repo, "get_by_id"):
            return self._repo.get_by_id(user_id)  # type: ignore[attr-defined]
        return None

    def create(self, user: User) -> User:
        """Create a user."""
        if self._repo is not None:
            return self._repo.save(user)
        self._users[user.user_id] = user
        return user

    def get(self, user_id: str) -> User | None:
        """Return a user by identifier."""
        if self._repo is not None:
            return self._repo_get(user_id)
        return self._users.get(user_id)

    def update(self, user_id: str, **changes) -> User:
        """Update a user."""
        if self._repo is not None and hasattr(self._repo, "update"):
            return self._repo.update(user_id, dict(changes))
        user = self._users[user_id]
        for key, value in changes.items():
            if hasattr(user, key):
                setattr(user, key, value)
        return user

    def disable(self, user_id: str) -> bool:
        """Disable a user when it exists."""
        user = self.get(user_id)
        if user is None:
            return False
        user.status = user.status.__class__.DISABLED
        if self._repo is not None:
            self.update(user_id, status=user.status)
        return True

    def search(self, term: str) -> list[User]:
        """Search for users matching the term."""
        if self._repo is not None and hasattr(self._repo, "search"):
            return self._repo.search(term)
        t = term.lower()
        return [
            u
            for u in self._users.values()
            if t in u.username.lower() or t in u.email.lower()
        ]

    def list(self) -> list[User]:
        """List users from the backing store."""
        if self._repo is not None:
            if hasattr(self._repo, "list_all"):
                return self._repo.list_all()
            if hasattr(self._repo, "list"):
                listed = self._repo.list()  # type: ignore[call-arg]
                if isinstance(listed, list):
                    return listed
                if hasattr(listed, "items"):
                    return list(listed.items)  # type: ignore[attr-defined]
        return list(self._users.values())

    def bootstrap_admin(
        self, username: str, email: str, *, force_password_change: bool = True
    ) -> User:
        """Create or return the bootstrap admin user."""
        for user in self.list():
            if user.username == username:
                return user
        admin = User(username=username, email=email, role="admin")
        setattr(admin, "force_password_change", force_password_change)
        return self.create(admin)
