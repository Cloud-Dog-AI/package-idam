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

# cloud_dog_idam — External RBAC mappers
"""LDAP/Keycloak role mapping and hybrid local+external role resolution."""

from __future__ import annotations

from dataclasses import dataclass


def map_external_groups(
    external_groups: list[str], group_map: dict[str, str]
) -> list[str]:
    """Handle map external groups."""
    return [group_map[g] for g in external_groups if g in group_map]


def map_external_roles(
    external_roles: list[str], role_map: dict[str, str]
) -> list[str]:
    """Handle map external roles."""
    mapped: list[str] = []
    for role in external_roles:
        local = role_map.get(role)
        if local and local not in mapped:
            mapped.append(local)
    return mapped


@dataclass(slots=True)
class LDAPGroupMapper:
    """Represent l d a p group mapper."""
    group_map: dict[str, str]

    def map(self, ldap_groups: list[str]) -> list[str]:
        """Handle map."""
        return map_external_groups(ldap_groups, self.group_map)


@dataclass(slots=True)
class KeycloakRoleMapper:
    """Represent keycloak role mapper."""
    realm_map: dict[str, str]
    client_map: dict[str, str]

    def map(self, realm_roles: list[str], client_roles: list[str]) -> list[str]:
        """Handle map."""
        mapped = map_external_roles(client_roles, self.client_map)
        mapped.extend(
            [
                r
                for r in map_external_roles(realm_roles, self.realm_map)
                if r not in mapped
            ]
        )
        return mapped


class HybridMapper:
    """Merge external and local role sets with local override semantics."""

    def merge(
        self,
        external_roles: set[str],
        local_roles: set[str],
        remove_external: set[str] | None = None,
    ) -> set[str]:
        """Handle merge."""
        remove_external = remove_external or set()
        base = {r for r in external_roles if r not in remove_external}
        base.update(local_roles)
        return base


class ExternalRoleSync:
    """Represent external role sync."""
    def __init__(self) -> None:
        self._roles_by_user: dict[str, set[str]] = {}

    def sync_external_roles(self, user_id: str, external_roles: list[str]) -> set[str]:
        """Handle sync external roles."""
        self._roles_by_user[user_id] = set(external_roles)
        return set(self._roles_by_user[user_id])

    def get_roles(self, user_id: str) -> set[str]:
        """Return roles."""
        return set(self._roles_by_user.get(user_id, set()))
