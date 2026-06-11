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

# cloud_dog_idam — Provider interface
"""Authentication provider base interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cloud_dog_idam.domain.models import AuthRequest, AuthResult


class AuthProvider(ABC):
    """Define the authentication provider contract."""

    @abstractmethod
    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Authenticate a request and return the auth result."""
        raise NotImplementedError

    @abstractmethod
    async def supports(self, auth_type: str) -> bool:
        """Return whether this provider supports the auth type."""
        raise NotImplementedError
