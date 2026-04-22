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

import pytest
from cloud_dog_idam.domain.models import AuthRequest
from cloud_dog_idam.providers.registry import ProviderRegistry
from cloud_dog_idam.testing.mock_providers import MockProvider


@pytest.mark.asyncio
async def test_provider_registry_dispatch() -> None:
    r = ProviderRegistry()
    r.register(MockProvider("api_key"))
    out = await r.authenticate(AuthRequest(auth_type="api_key", secret="x"))
    assert out.claims["auth_type"] == "api_key"


@pytest.mark.asyncio
async def test_provider_registry_priority_and_listing() -> None:
    r = ProviderRegistry()
    low = MockProvider("api_key")
    high = MockProvider("api_key")
    r.register(low, priority=50)
    r.register(high, priority=10)
    listing = r.list_providers()
    assert listing[0][1] == high.__class__.__name__
    out = await r.authenticate(AuthRequest(auth_type="api_key", secret="x"))
    assert out.claims["auth_type"] == "api_key"
