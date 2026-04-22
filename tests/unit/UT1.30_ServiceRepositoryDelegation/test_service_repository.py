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

"""Ensure services delegate to provided repositories."""

from __future__ import annotations

from cloud_dog_idam.domain.enums import ProviderType
from cloud_dog_idam.domain.models import Group, IdentityLink, Role, User
from cloud_dog_idam.identity.service import IdentityService
from cloud_dog_idam.users.groups import GroupService
from cloud_dog_idam.users.roles import RoleService
from cloud_dog_idam.users.service import UserService


def test_services_delegate_to_repository() -> None:
    class UserRepo:
        def __init__(self) -> None:
            self.saved: list[User] = []

        def save(self, user: User) -> User:
            self.saved.append(user)
            return user

        def get(self, user_id: str) -> User | None:
            return next((u for u in self.saved if u.user_id == user_id), None)

        def update(self, user_id: str, changes: dict[str, object]) -> User:
            user = self.get(user_id)
            assert user is not None
            for key, value in changes.items():
                setattr(user, key, value)
            return user

        def search(self, term: str) -> list[User]:
            return [u for u in self.saved if term in u.username]

        def list_all(self) -> list[User]:
            return list(self.saved)

    class GroupRepo:
        def __init__(self) -> None:
            self.saved: list[Group] = []
            self.members_map: dict[str, set[str]] = {}

        def save(self, group: Group) -> Group:
            self.saved.append(group)
            return group

        def list_all(self) -> list[Group]:
            return list(self.saved)

        def add_member(self, group_id: str, user_id: str) -> None:
            self.members_map.setdefault(group_id, set()).add(user_id)

        def members(self, group_id: str) -> set[str]:
            return set(self.members_map.get(group_id, set()))

    class RoleRepo:
        def __init__(self) -> None:
            self.saved: list[Role] = []
            self.assignments: dict[str, set[str]] = {}

        def save(self, role: Role) -> Role:
            self.saved.append(role)
            return role

        def list_all(self) -> list[Role]:
            return list(self.saved)

        def assign(self, user_id: str, role_name: str) -> None:
            self.assignments.setdefault(user_id, set()).add(role_name)

        def assigned(self, user_id: str) -> set[str]:
            return set(self.assignments.get(user_id, set()))

    class LinkRepo:
        def __init__(self) -> None:
            self.links: list[IdentityLink] = []

        def save_link(self, link: IdentityLink) -> IdentityLink:
            self.links.append(link)
            return link

        def remove_link(self, identity_id: str) -> None:
            self.links = [i for i in self.links if i.identity_id != identity_id]

        def list_links(self) -> list[IdentityLink]:
            return list(self.links)

    class UserStore:
        def __init__(self) -> None:
            self.users: dict[str, User] = {}

        def save_user(self, user: User) -> User:
            self.users[user.user_id] = user
            return user

        def get_user(self, user_id: str) -> User | None:
            return self.users.get(user_id)

    user_repo = UserRepo()
    group_repo = GroupRepo()
    role_repo = RoleRepo()
    link_repo = LinkRepo()
    user_store = UserStore()

    users = UserService(repository=user_repo)
    groups = GroupService(repository=group_repo)
    roles = RoleService(repository=role_repo)
    identities = IdentityService(link_repository=link_repo, user_repository=user_store)

    user = users.create(User(username="repo-user", email="repo@example.test"))
    assert user_repo.saved[0].user_id == user.user_id
    assert users.get(user.user_id) is not None

    group = groups.create(Group(name="ops"))
    groups.add_member(group.group_id, user.user_id)
    assert user.user_id in groups.members(group.group_id)

    role = roles.create(Role(name="admin"))
    roles.assign(user.user_id, role.name)
    assert role.name in roles.get_assigned(user.user_id)

    identities.upsert_user(user)
    link = IdentityLink(
        provider_type=ProviderType.OIDC,
        provider_id="auth0",
        subject="sub-123",
    )
    identities.link_identity(user.user_id, link)
    found = identities.find_by_external_id("auth0", "sub-123")
    assert found is not None
    assert found.user_id == user.user_id
