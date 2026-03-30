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

"""Validate lightweight API-key-only authentication provider behaviour."""

from __future__ import annotations

import pytest

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest
from cloud_dog_idam.providers.api_key_only import APIKeyOnlyProvider


@pytest.mark.asyncio
async def test_api_key_only_supports_expected_auth_types() -> None:
    provider = APIKeyOnlyProvider(key_role_mapping={"raw-1": "admin"})
    assert await provider.supports("api_key") is True
    assert await provider.supports("api_key_only") is True
    assert await provider.supports("oidc") is False


@pytest.mark.asyncio
async def test_api_key_only_authenticates_and_returns_role_claim() -> None:
    provider = APIKeyOnlyProvider(key_role_mapping={"raw-1": "admin"})
    out = await provider.authenticate(
        AuthRequest(auth_type="api_key_only", secret="raw-1")
    )
    assert out.user.role == "admin"
    assert out.user.is_system_user is True
    assert out.claims["auth_type"] == "api_key_only"


@pytest.mark.asyncio
async def test_api_key_only_rejects_invalid_key() -> None:
    provider = APIKeyOnlyProvider(key_role_mapping={"raw-1": "admin"})
    with pytest.raises(AuthenticationError):
        await provider.authenticate(AuthRequest(auth_type="api_key", secret="bad"))


@pytest.mark.asyncio
async def test_api_key_only_can_be_created_from_config() -> None:
    provider = APIKeyOnlyProvider.from_config(
        {
            "default_role": "viewer",
            "keys": [{"key": "raw-a", "role": "user"}],
        }
    )
    out = await provider.authenticate(
        AuthRequest(auth_type="api_key_only", secret="raw-a")
    )
    assert out.user.role == "user"
