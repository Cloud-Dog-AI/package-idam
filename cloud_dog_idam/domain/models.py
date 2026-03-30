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

# cloud_dog_idam — Domain models
"""Canonical domain models for users, roles, groups, keys, and auth requests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cloud_dog_idam.domain.enums import ProviderType, UserStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class User:
    """Represent user."""
    user_id: str = field(default_factory=lambda: str(uuid4()))
    username: str = ""
    email: str = ""
    display_name: str = ""
    status: UserStatus = UserStatus.ACTIVE
    role: str = "viewer"
    is_system_user: bool = False
    tenant_id: str | None = None
    password_hash: str = ""
    force_password_change: bool = False
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)


@dataclass(slots=True)
class Group:
    """Represent group."""
    group_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    tenant_id: str | None = None


@dataclass(slots=True)
class Role:
    """Represent role."""
    role_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    permissions: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ApiKey:
    """Represent api key."""
    api_key_id: str = field(default_factory=lambda: str(uuid4()))
    owner_user_id: str = ""
    key_prefix: str = "cd_"
    key_hash: str = ""
    status: str = "active"
    expires_at: datetime | None = None


@dataclass(slots=True)
class IdentityLink:
    """Represent identity link."""
    identity_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: str = ""
    provider_type: ProviderType = ProviderType.OIDC
    provider_id: str = ""
    subject: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Policy:
    """Represent policy."""
    policy_id: str = field(default_factory=lambda: str(uuid4()))
    policy_type: str = ""
    config_json: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AuthRequest:
    """Represent auth request."""
    auth_type: str
    principal: str = ""
    secret: str = ""
    bearer_token: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AuthResult:
    """Represent auth result."""
    user: User
    identity_link: IdentityLink | None = None
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TokenPair:
    """Represent token pair."""
    access_token: str
    refresh_token: str | None
    token_type: str = "Bearer"
    expires_in: int = 3600
