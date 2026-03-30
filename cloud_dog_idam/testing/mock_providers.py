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

# cloud_dog_idam — Mock providers
"""Mock authentication providers for service and integration tests."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, IdentityLink, User
from cloud_dog_idam.providers.base import AuthProvider


class MockProvider(AuthProvider):
    """Simple provider that always authenticates with a static user."""

    def __init__(self, auth_type: str, user: User | None = None) -> None:
        self._auth_type = auth_type
        self._user = user or User(username="mock", email="mock@example.com")

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == self._auth_type

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        return AuthResult(user=self._user, claims={"auth_type": self._auth_type})


@dataclass(slots=True)
class MockOIDCProvider(MockProvider):
    """OIDC-like mock that returns identity-link data and subject claims."""

    provider_id: str = "mock-oidc"
    subject: str = "sub-mock-user"

    def __init__(
        self,
        *,
        provider_id: str = "mock-oidc",
        subject: str = "sub-mock-user",
        user: User | None = None,
    ) -> None:
        super().__init__("oidc", user=user)
        self.provider_id = provider_id
        self.subject = subject

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        claims = {
            "sub": self.subject,
            "email": self._user.email,
            "provider": self.provider_id,
        }
        link = IdentityLink(
            user_id=self._user.user_id,
            provider_id=self.provider_id,
            subject=self.subject,
            attributes=claims,
        )
        return AuthResult(user=self._user, identity_link=link, claims=claims)


class MockFailingProvider(AuthProvider):
    """Provider that intentionally fails authentication for negative tests."""

    def __init__(
        self, auth_type: str, message: str = "Mock authentication failure"
    ) -> None:
        self._auth_type = auth_type
        self._message = message

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == self._auth_type

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        raise AuthenticationError(self._message)
