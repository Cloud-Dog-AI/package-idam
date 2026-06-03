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

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest
from cloud_dog_idam.providers.os_pam import OSPAMProvider


@pytest.mark.asyncio
async def test_os_pam_provider_handles_missing_runtime() -> None:
    provider = OSPAMProvider()
    with pytest.raises(AuthenticationError):
        await provider.authenticate(
            AuthRequest(auth_type="os_pam", principal="x", secret="x")
        )
