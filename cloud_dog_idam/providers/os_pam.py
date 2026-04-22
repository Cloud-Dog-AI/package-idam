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

# cloud_dog_idam — OS/PAM provider
"""Authenticate local system users via Linux PAM."""

from __future__ import annotations

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, User
from cloud_dog_idam.providers.base import AuthProvider

try:
    import pam  # type: ignore
except ImportError:  # pragma: no cover
    pam = None


class OSPAMProvider(AuthProvider):
    """Represent o s p a m provider."""
    def __init__(self, *, service: str = "login") -> None:
        self._service = service

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == "os_pam"

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        if pam is None:
            raise AuthenticationError("python-pam is not installed")
        client = pam.pam()
        ok = client.authenticate(
            request.principal, request.secret, service=self._service
        )
        if not ok:
            raise AuthenticationError("PAM authentication failed")
        return AuthResult(
            user=User(username=request.principal, email=f"{request.principal}@local")
        )
