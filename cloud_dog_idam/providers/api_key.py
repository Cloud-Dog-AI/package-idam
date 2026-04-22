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

# cloud_dog_idam — API key provider
"""Authenticate requests by API key."""

from __future__ import annotations

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.domain.enums import UserStatus
from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, User
from cloud_dog_idam.providers.base import AuthProvider


class APIKeyProvider(AuthProvider):
    """Represent a p i key provider."""
    def __init__(self, manager: APIKeyManager, user_lookup) -> None:
        self._manager = manager
        self._user_lookup = user_lookup

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == "api_key"

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        key = self._manager.validate(request.secret)
        if key is None:
            raise AuthenticationError("Invalid API key")
        user = self._user_lookup(key.owner_user_id)
        if user is None:
            user = User(
                user_id=key.owner_user_id, username="system", is_system_user=True
            )
        # W28A-551: Reject keys whose owner is disabled or locked
        if hasattr(user, "status") and user.status in {UserStatus.DISABLED, UserStatus.LOCKED}:
            raise AuthenticationError("User account is disabled")
        return AuthResult(user=user)
