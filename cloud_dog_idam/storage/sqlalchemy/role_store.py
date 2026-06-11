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

# cloud_dog_idam — DB-backed role store
"""Persist roles AND their permissions via the ``role_permissions`` join table.

This closes the PS-71 §IW3A gap where roles existed only as an in-memory stub:
``RoleService`` could create role names but role->permission links were never
persisted, so the IW3A.1 ``permissions`` column had no durable source.

``SqlAlchemyRoleStore`` implements the ``RoleService`` repository protocol
(``save`` / ``list_all`` / ``assign`` / ``assigned``) plus ``get`` / ``get_by_name``
/ ``update`` / ``delete`` / ``seed_baseline`` / ``list_response``. Permissions are
normalised into ``PermissionORM`` rows and linked through ``RolePermissionORM``
(the M:N join table), so a role's permissions survive a process/engine restart.

Related: PS-70 §UM (roles/permissions/RBAC bindings), PS-71 §IW3A, rbac/role_catalog.py.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from cloud_dog_idam.domain.models import Role
from cloud_dog_idam.rbac.role_catalog import (
    BASELINE_ROLE_NAMES,
    BASELINE_ROLE_PERMISSIONS,
)
from cloud_dog_idam.storage.sqlalchemy import models as m


class BaselineRoleProtected(Exception):
    """Raised when a delete targets a baseline (``admin``/``user``) role (IW3A.4)."""


class SqlAlchemyRoleStore:
    """Role + role-permission persistence over the canonical IDAM tables."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- permission persistence ----------------------------------------------------
    def _ensure_permission(self, permission: str) -> str:
        """Ensure a ``PermissionORM`` row exists for a permission string.

        The full permission string is the stable ``permission_id``; ``resource`` and
        ``action`` are derived for human-readable queries (``a.b.c`` -> ``a.b``/``c``;
        ``a:b`` -> ``a``/``b``).
        """
        existing = self._session.get(m.PermissionORM, permission)
        if existing is not None:
            return permission
        if "." in permission:
            resource, _, action = permission.rpartition(".")
        elif ":" in permission:
            resource, _, action = permission.partition(":")
        else:
            resource, action = permission, ""
        self._session.add(
            m.PermissionORM(
                permission_id=permission,
                resource=resource or permission,
                action=action or permission,
            )
        )
        return permission

    def _sync_permissions(self, role_id: str, permissions: set[str]) -> None:
        self._session.execute(
            delete(m.RolePermissionORM).where(m.RolePermissionORM.role_id == role_id)
        )
        for perm in sorted(permissions):
            permission_id = self._ensure_permission(perm)
            self._session.add(
                m.RolePermissionORM(role_id=role_id, permission_id=permission_id)
            )

    def _permissions_for(self, role_id: str) -> set[str]:
        return set(
            self._session.scalars(
                select(m.RolePermissionORM.permission_id).where(
                    m.RolePermissionORM.role_id == role_id
                )
            )
        )

    def _to_domain(self, orm: m.RoleORM) -> Role:
        return Role(
            role_id=orm.role_id,
            name=orm.name,
            description=orm.description,
            permissions=self._permissions_for(orm.role_id),
        )

    # -- RoleService repository protocol -------------------------------------------
    def save(self, role: Role) -> Role:
        """Create or update a role (upsert by id, then by unique name) + permissions."""
        orm = self._session.get(m.RoleORM, role.role_id)
        if orm is None:
            orm = self._session.scalar(
                select(m.RoleORM).where(m.RoleORM.name == role.name)
            )
        if orm is None:
            orm = m.RoleORM(
                role_id=role.role_id, name=role.name, description=role.description
            )
            self._session.add(orm)
        else:
            orm.name = role.name
            orm.description = role.description
            role.role_id = orm.role_id
        self._session.flush()
        self._sync_permissions(orm.role_id, set(role.permissions))
        self._session.commit()
        return self._to_domain(orm)

    def list_all(self) -> list[Role]:
        """Return all roles with their permissions."""
        return [self._to_domain(o) for o in self._session.scalars(select(m.RoleORM))]

    def get(self, role_id: str) -> Role | None:
        """Return one role by id, or None."""
        orm = self._session.get(m.RoleORM, role_id)
        return self._to_domain(orm) if orm is not None else None

    def get_by_name(self, name: str) -> Role | None:
        """Return one role by unique name, or None."""
        orm = self._session.scalar(select(m.RoleORM).where(m.RoleORM.name == name))
        return self._to_domain(orm) if orm is not None else None

    def update(
        self,
        role_id: str,
        *,
        description: str | None = None,
        permissions: set[str] | None = None,
    ) -> Role:
        """Update a role's description and/or permission set."""
        orm = self._session.get(m.RoleORM, role_id)
        if orm is None:
            raise KeyError(role_id)
        if description is not None:
            orm.description = description
        self._session.flush()
        if permissions is not None:
            self._sync_permissions(role_id, set(permissions))
        self._session.commit()
        return self._to_domain(orm)

    def delete(self, role_id: str) -> bool:
        """Delete a role + its permission links. Baseline roles are protected."""
        orm = self._session.get(m.RoleORM, role_id)
        if orm is None:
            return False
        if orm.name in BASELINE_ROLE_NAMES:
            raise BaselineRoleProtected(orm.name)
        self._session.execute(
            delete(m.RolePermissionORM).where(m.RolePermissionORM.role_id == role_id)
        )
        self._session.delete(orm)
        self._session.commit()
        return True

    # -- user<->role assignment (user_roles) ---------------------------------------
    def assign(self, user_id: str, role_name: str) -> None:
        """Assign a role (by name) to a user, creating the role if absent."""
        role = self.get_by_name(role_name)
        if role is None:
            role = self.save(Role(name=role_name))
        if self._session.get(m.UserRoleORM, (user_id, role.role_id)) is None:
            self._session.add(m.UserRoleORM(user_id=user_id, role_id=role.role_id))
            self._session.commit()

    def assigned(self, user_id: str) -> set[str]:
        """Return the set of role NAMES assigned to a user."""
        role_ids = list(
            self._session.scalars(
                select(m.UserRoleORM.role_id).where(m.UserRoleORM.user_id == user_id)
            )
        )
        names: set[str] = set()
        for role_id in role_ids:
            orm = self._session.get(m.RoleORM, role_id)
            if orm is not None:
                names.add(orm.name)
        return names

    # -- seeding + API response shape ----------------------------------------------
    def seed_baseline(self) -> list[Role]:
        """Idempotently ensure baseline ``admin``/``user`` roles exist (IW3A.4)."""
        result: list[Role] = []
        for name, perms in BASELINE_ROLE_PERMISSIONS.items():
            existing = self.get_by_name(name)
            if existing is None:
                result.append(
                    self.save(
                        Role(
                            name=name,
                            description=f"Baseline {name} role",
                            permissions=set(perms),
                        )
                    )
                )
            else:
                result.append(existing)
        return result

    def list_response(self) -> list[dict]:
        """Return roles in the PS-71 §IW3A.1 column shape.

        Columns: ``name``, ``description``, ``permissions`` (chip list), ``created``.
        """
        rows: list[dict] = []
        for orm in self._session.scalars(select(m.RoleORM)):
            rows.append(
                {
                    "role_id": orm.role_id,
                    "name": orm.name,
                    "description": orm.description,
                    "permissions": sorted(self._permissions_for(orm.role_id)),
                    "created": orm.created_at.isoformat() if orm.created_at else None,
                    "baseline": orm.name in BASELINE_ROLE_NAMES,
                }
            )
        return rows
