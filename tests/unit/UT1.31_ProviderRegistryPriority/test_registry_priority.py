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

"""Validate priority ordering, listing, and deregistration behaviour."""

from __future__ import annotations

import pytest

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest
from cloud_dog_idam.providers.registry import ProviderRegistry
from cloud_dog_idam.testing.mock_providers import MockProvider


@pytest.mark.asyncio
async def test_registry_priority_listing_and_deregister() -> None:
    registry = ProviderRegistry()
    provider_slow = MockProvider("api_key")
    provider_fast = MockProvider("api_key")

    registry.register(provider_slow, priority=50)
    registry.register(provider_fast, priority=10)

    listing = registry.list_providers()
    assert listing[0][1] == provider_fast.__class__.__name__

    out = await registry.authenticate(AuthRequest(auth_type="api_key", secret="secret"))
    assert out.claims["auth_type"] == "api_key"

    removed = registry.deregister("api_key")
    assert removed == 2
    with pytest.raises(AuthenticationError):
        await registry.authenticate(AuthRequest(auth_type="api_key", secret="secret"))
