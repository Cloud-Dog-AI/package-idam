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

# cloud_dog_idam — SQLAlchemy repositories
"""Repository layer for all IDAM entities with CRUD/pagination/filtering."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cloud_dog_idam.storage.sqlalchemy import models as m

T = TypeVar("T")


@dataclass(slots=True)
class PaginationParams:
    """Represent pagination params."""
    page: int = 1
    page_size: int = 20


@dataclass(slots=True)
class PaginatedResult(Generic[T]):
    """Represent paginated result."""
    items: list[T]
    page: int
    page_size: int
    total: int


class BaseRepository(Generic[T]):
    """Represent base repository."""
    orm_model: type

    def __init__(self, session: Session, *, tenant_id: str | None = None) -> None:
        self._session = session
        self._tenant_id = tenant_id

    def save(self, entity: T) -> T:
        """Handle save."""
        self._session.add(entity)
        self._session.commit()
        return entity

    def get_by_id(self, entity_id: str) -> T | None:
        """Return by id."""
        return self._session.get(self.orm_model, entity_id)

    def _apply_filters(self, query, filters: dict[str, Any] | None = None):
        filters = filters or {}
        for key, value in filters.items():
            if hasattr(self.orm_model, key):
                query = query.where(getattr(self.orm_model, key) == value)
        if self._tenant_id and hasattr(self.orm_model, "tenant_id"):
            query = query.where(getattr(self.orm_model, "tenant_id") == self._tenant_id)
        return query

    def list(
        self, pagination: PaginationParams, filters: dict[str, Any] | None = None
    ) -> PaginatedResult[T]:
        """Handle list."""
        query = self._apply_filters(select(self.orm_model), filters)
        total = (
            self._session.scalar(select(func.count()).select_from(query.subquery()))
            or 0
        )
        offset = max(0, (pagination.page - 1) * pagination.page_size)
        items = list(
            self._session.scalars(query.offset(offset).limit(pagination.page_size))
        )
        return PaginatedResult(
            items=items,
            page=pagination.page,
            page_size=pagination.page_size,
            total=int(total),
        )

    def update(self, entity_id: str, data: dict[str, Any]) -> T:
        """Handle update."""
        entity = self.get_by_id(entity_id)
        if entity is None:
            raise KeyError(entity_id)
        for key, value in data.items():
            if hasattr(entity, key):
                setattr(entity, key, value)
        self._session.commit()
        return entity

    def delete(self, entity_id: str, soft: bool = True) -> bool:
        """Handle delete."""
        entity = self.get_by_id(entity_id)
        if entity is None:
            return False
        if soft and hasattr(entity, "status"):
            setattr(entity, "status", "deleted")
        else:
            self._session.delete(entity)
        self._session.commit()
        return True

    def count(self, filters: dict[str, Any] | None = None) -> int:
        """Handle count."""
        query = self._apply_filters(select(self.orm_model), filters)
        total = (
            self._session.scalar(select(func.count()).select_from(query.subquery()))
            or 0
        )
        return int(total)


class UserRepository(BaseRepository[m.UserORM]):
    """Represent user repository."""
    orm_model = m.UserORM

    def by_username(self, username: str) -> m.UserORM | None:
        """Handle by username."""
        return self._session.scalar(
            select(m.UserORM).where(m.UserORM.username == username)
        )

    def by_email(self, email: str) -> m.UserORM | None:
        """Handle by email."""
        return self._session.scalar(select(m.UserORM).where(m.UserORM.email == email))

    def search(
        self, query: str, pagination: PaginationParams
    ) -> PaginatedResult[m.UserORM]:
        """Handle search."""
        q = self._apply_filters(
            select(m.UserORM).where(
                (m.UserORM.username.ilike(f"%{query}%"))
                | (m.UserORM.email.ilike(f"%{query}%"))
            )
        )
        total = (
            self._session.scalar(select(func.count()).select_from(q.subquery())) or 0
        )
        offset = max(0, (pagination.page - 1) * pagination.page_size)
        items = list(
            self._session.scalars(q.offset(offset).limit(pagination.page_size))
        )
        return PaginatedResult(
            items=items,
            page=pagination.page,
            page_size=pagination.page_size,
            total=int(total),
        )


class IdentityRepository(BaseRepository[m.IdentityORM]):
    """Represent identity repository."""
    orm_model = m.IdentityORM

    def by_external_id(self, provider_id: str, subject: str) -> m.IdentityORM | None:
        """Handle by external id."""
        return self._session.scalar(
            select(m.IdentityORM).where(
                m.IdentityORM.provider_id == provider_id,
                m.IdentityORM.subject == subject,
            )
        )

    def by_user_id(self, user_id: str) -> list[m.IdentityORM]:
        """Handle by user id."""
        return list(
            self._session.scalars(
                select(m.IdentityORM).where(m.IdentityORM.user_id == user_id)
            )
        )


class GroupRepository(BaseRepository[m.GroupORM]):
    """Represent group repository."""
    orm_model = m.GroupORM

    def by_name(self, name: str) -> m.GroupORM | None:
        """Handle by name."""
        return self._session.scalar(select(m.GroupORM).where(m.GroupORM.name == name))


class RoleRepository(BaseRepository[m.RoleORM]):
    """Represent role repository."""
    orm_model = m.RoleORM


class GroupMembershipRepository(BaseRepository[m.GroupMembershipORM]):
    """Represent group membership repository."""
    orm_model = m.GroupMembershipORM


class UserRoleRepository(BaseRepository[m.UserRoleORM]):
    """Represent user role repository."""
    orm_model = m.UserRoleORM


class GroupRoleRepository(BaseRepository[m.GroupRoleORM]):
    """Represent group role repository."""
    orm_model = m.GroupRoleORM


class PermissionRepository(BaseRepository[m.PermissionORM]):
    """Represent permission repository."""
    orm_model = m.PermissionORM


class RolePermissionRepository(BaseRepository[m.RolePermissionORM]):
    """Represent role permission repository."""
    orm_model = m.RolePermissionORM


class APIKeyRepository(BaseRepository[m.APIKeyORM]):
    """Represent a p i key repository."""
    orm_model = m.APIKeyORM

    def by_key_hash(self, key_hash: str) -> m.APIKeyORM | None:
        """Handle by key hash."""
        return self._session.scalar(
            select(m.APIKeyORM).where(m.APIKeyORM.key_hash == key_hash)
        )

    def by_owner(self, owner_user_id: str) -> list[m.APIKeyORM]:
        """Handle by owner."""
        return list(
            self._session.scalars(
                select(m.APIKeyORM).where(m.APIKeyORM.owner_user_id == owner_user_id)
            )
        )


class RefreshTokenRepository(BaseRepository[m.RefreshTokenORM]):
    """Represent refresh token repository."""
    orm_model = m.RefreshTokenORM


class SessionRepository(BaseRepository[m.SessionORM]):
    """Represent session repository."""
    orm_model = m.SessionORM

    def active_sessions(self, user_id: str) -> list[m.SessionORM]:
        """Handle active sessions."""
        return list(
            self._session.scalars(
                select(m.SessionORM).where(
                    m.SessionORM.user_id == user_id, m.SessionORM.status == "active"
                )
            )
        )


class PolicyRepository(BaseRepository[m.PolicyORM]):
    """Represent policy repository."""
    orm_model = m.PolicyORM


class AuditEventRepository(BaseRepository[m.AuditEventORM]):
    """Represent audit event repository."""
    orm_model = m.AuditEventORM

    def delete(self, entity_id: str, soft: bool = True) -> bool:
        """Handle delete."""
        return False
