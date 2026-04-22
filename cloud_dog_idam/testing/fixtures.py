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

# cloud_dog_idam — Test fixtures
"""Shared fixture factories for conformance and integration tests."""

from __future__ import annotations

import uuid

from cloud_dog_idam.domain.enums import ProviderType
from cloud_dog_idam.domain.models import ApiKey, Group, IdentityLink, Role, User


def demo_user(
    username: str = "demo",
    email: str = "demo@example.com",
    role: str = "user",
) -> User:
    """Create a demo user with sensible defaults."""
    return User(username=username, email=email, role=role)


def demo_admin() -> User:
    """Create a demo administrator user."""
    return User(username="admin", email="admin@example.com", role="admin")


def demo_group(name: str = "developers") -> Group:
    """Create a demo group."""
    return Group(name=name, description=f"Demo group: {name}")


def demo_role(name: str = "viewer") -> Role:
    """Create a demo role."""
    return Role(name=name, description=f"Demo role: {name}")


def demo_identity_link(user_id: str, provider: str = "keycloak") -> IdentityLink:
    """Create a demo identity link."""
    return IdentityLink(
        user_id=user_id,
        provider_type=ProviderType.OIDC,
        provider_id=provider,
        subject=f"sub-{uuid.uuid4().hex[:8]}",
    )


def demo_api_key(owner_user_id: str, prefix: str = "cd_") -> ApiKey:
    """Create an API key model for test setup."""
    return ApiKey(
        owner_user_id=owner_user_id,
        key_prefix=prefix,
        key_hash=f"hash-{uuid.uuid4().hex}",
        status="active",
    )
