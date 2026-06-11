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

# cloud_dog_idam — Membership resolver port (W28A-741: IDAM-B2 §4.1 step 2)
"""Membership resolver port for the effective-grants resolver.

The W28A-741 keystone (``rbac.grants``) composes role-derived permissions with
``RBACBinding`` rows on the user AND on every group the user is a member of.
The user-to-group relation lives in different places per service today:

  - shared ``group_memberships`` SQLAlchemy table (``cloud_dog_idam``'s
    default; covers most services)
  - file-mcp ``FileAdminGroupMember`` (FKs ``group_id``→``file_admin_groups``,
    ``user_id``→``file_admin_users``)
  - expert-agent ``Group.members[]`` JSON list on the group row
  - etc.

This module defines the abstract Protocol the resolver depends on and ships a
default SQLAlchemy implementation that uses the shared ``group_memberships``
table. Services with their own membership table provide an adapter and inject
it where the resolver is wired (per ``cloud_dog_idam.api.fastapi.deps.require_permission``
or the host application).

Per IDAM-B2 §4.1 step 2: "One interface, service-supplied query."
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@runtime_checkable
class MembershipResolver(Protocol):
    """Resolve the set of group ids a user is a member of.

    The resolver is called once per ``effective_grants(user_id)`` invocation.
    Caching is handled by ``RBACEngine._cache`` at the ``grants:{uid}`` key, so
    implementations can be straightforward DB reads — the engine cache
    invalidation (extended in W28A-741) ensures the resolved set is fresh
    after any ``add_user_to_group``/``remove_user_from_group``.
    """

    def groups_of(self, user_id: str) -> set[str]:
        """Return the set of ``group_id`` values the user is currently a member of."""
        ...


class SqlAlchemyMembershipResolver:
    """Default implementation backed by the shared ``group_memberships`` table.

    Used by services that consume ``cloud_dog_idam`` without their own
    bespoke membership store. Services with bespoke tables (file-mcp, ...) ship
    a small adapter class implementing the same ``MembershipResolver`` Protocol.
    """

    def __init__(self, session: "Session") -> None:
        """Store the SQLAlchemy session; queries are lazy."""
        self._session = session

    def groups_of(self, user_id: str) -> set[str]:
        """Return ``group_id`` set for the user via the shared ``group_memberships`` table."""
        # Lazy import keeps the module importable in environments that don't
        # install SQLAlchemy (e.g. lightweight tests). Membership queries
        # naturally require the full storage stack.
        from sqlalchemy import select

        from cloud_dog_idam.storage.sqlalchemy.models import GroupMembershipORM

        rows = self._session.scalars(
            select(GroupMembershipORM.group_id).where(
                GroupMembershipORM.user_id == user_id,
            )
        )
        return {str(g) for g in rows}


class StaticMembershipResolver:
    """Pure in-memory resolver — useful for unit tests and synthetic seeds.

    Constructor takes a ``dict[user_id, set[group_id]]``. The
    ``AT1.N_CascadeResolves`` test uses this resolver to prove the resolver
    logic without a real DB, while ``AT1.N_BindingWriteAPI`` uses the real
    ``SqlAlchemyMembershipResolver`` against a test SQLite to prove the
    end-to-end persistence + cascade.
    """

    def __init__(self, memberships: dict[str, set[str]] | None = None) -> None:
        """Store the static memberships dict; copy on read to prevent mutation aliasing."""
        self._memberships: dict[str, set[str]] = {
            uid: set(gids) for uid, gids in (memberships or {}).items()
        }

    def groups_of(self, user_id: str) -> set[str]:
        """Return the set of group_ids for ``user_id`` (or empty set if unknown)."""
        return set(self._memberships.get(user_id, set()))

    def add(self, user_id: str, group_id: str) -> None:
        """Add a static membership (test fixture helper)."""
        self._memberships.setdefault(user_id, set()).add(group_id)

    def remove(self, user_id: str, group_id: str) -> None:
        """Remove a static membership (test fixture helper)."""
        if user_id in self._memberships:
            self._memberships[user_id].discard(group_id)
