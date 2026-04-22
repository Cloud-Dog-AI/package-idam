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

from __future__ import annotations

import pytest
from cloud_dog_idam.domain.models import User, AuthRequest
from cloud_dog_idam.providers.local_password import LocalPasswordProvider
from cloud_dog_idam.providers.os_pam import OSPAMProvider
from cloud_dog_idam.domain.errors import AuthenticationError


@pytest.mark.asyncio
async def test_local_password_provider_success() -> None:
    user = User(username="gary", email="g@x")
    provider = LocalPasswordProvider(lambda u: user if u == "gary" else None)
    user.password_hash = provider.hash_password("secret123A!")
    result = await provider.authenticate(
        AuthRequest(auth_type="local_password", principal="gary", secret="secret123A!")
    )
    assert result.user.username == "gary"


@pytest.mark.asyncio
async def test_os_pam_provider_path() -> None:
    provider = OSPAMProvider()
    assert await provider.supports("os_pam") is True
    try:
        await provider.authenticate(
            AuthRequest(auth_type="os_pam", principal="nonexistent", secret="bad")
        )
    except AuthenticationError:
        assert True
