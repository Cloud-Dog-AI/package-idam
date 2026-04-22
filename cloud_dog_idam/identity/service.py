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

# cloud_dog_idam — Identity service
"""Manage identity links and external-provider lookups."""

from __future__ import annotations

from typing import Protocol

from cloud_dog_idam.domain.models import IdentityLink, User


class IdentityLinkRepository(Protocol):
    """Represent identity link repository."""

    def save_link(self, link: IdentityLink) -> IdentityLink:
        """Persist an identity link."""
        ...

    def remove_link(self, identity_id: str) -> None:
        """Remove an identity link by identifier."""
        ...

    def list_links(self) -> list[IdentityLink]:
        """List stored identity links."""
        ...


class UserStoreRepository(Protocol):
    """Represent user store repository."""

    def save_user(self, user: User) -> User:
        """Persist a user record."""
        ...

    def get_user(self, user_id: str) -> User | None:
        """Return a user by identifier."""
        ...


class IdentityService:
    """Manage external identity links and user lookups."""

    def __init__(
        self,
        *,
        link_repository: IdentityLinkRepository | None = None,
        user_repository: UserStoreRepository | None = None,
    ) -> None:
        self._link_repo = link_repository
        self._user_repo = user_repository
        self._links: dict[str, IdentityLink] = {}
        self._users: dict[str, User] = {}

    def link_identity(self, user_id: str, link: IdentityLink) -> None:
        """Link an external identity to a user."""
        link.user_id = user_id
        if self._link_repo is not None and hasattr(self._link_repo, "save_link"):
            self._link_repo.save_link(link)
            return
        self._links[link.identity_id] = link

    def unlink_identity(self, identity_id: str) -> None:
        """Remove an identity link."""
        if self._link_repo is not None and hasattr(self._link_repo, "remove_link"):
            self._link_repo.remove_link(identity_id)
            return
        self._links.pop(identity_id, None)

    def _iter_links(self) -> list[IdentityLink]:
        if self._link_repo is not None and hasattr(self._link_repo, "list_links"):
            return self._link_repo.list_links()
        return list(self._links.values())

    def _get_user(self, user_id: str) -> User | None:
        if self._user_repo is not None and hasattr(self._user_repo, "get_user"):
            return self._user_repo.get_user(user_id)
        return self._users.get(user_id)

    def find_by_external_id(self, provider: str, subject: str) -> User | None:
        """Find a user by external provider and subject."""
        for link in self._iter_links():
            if link.provider_id == provider and link.subject == subject:
                return self._get_user(link.user_id)
        return None

    def upsert_user(self, user: User) -> User:
        """Insert or update a user in the backing store."""
        if self._user_repo is not None and hasattr(self._user_repo, "save_user"):
            return self._user_repo.save_user(user)
        self._users[user.user_id] = user
        return user
