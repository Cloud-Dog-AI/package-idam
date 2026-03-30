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

# cloud_dog_idam — Provider registry
"""Authentication provider registration, ordering, and dispatch."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult
from cloud_dog_idam.providers.base import AuthProvider


@dataclass(slots=True)
class _ProviderEntry:
    priority: int
    order: int
    provider: AuthProvider


class ProviderRegistry:
    """Represent provider registry."""
    def __init__(self) -> None:
        self._providers: list[_ProviderEntry] = []
        self._next_order = 0

    def register(self, provider: AuthProvider, priority: int = 100) -> None:
        """Handle register."""
        self._providers.append(
            _ProviderEntry(priority=priority, order=self._next_order, provider=provider)
        )
        self._next_order += 1
        self._providers.sort(key=lambda item: (item.priority, item.order))

    def deregister(self, auth_type: str) -> int:
        """Handle deregister."""
        before = len(self._providers)
        self._providers = [
            item
            for item in self._providers
            if getattr(item.provider, "_auth_type", None) != auth_type
        ]
        return before - len(self._providers)

    def list_providers(self) -> list[tuple[str, str]]:
        """List providers."""
        listing: list[tuple[str, str]] = []
        for item in self._providers:
            auth_type = getattr(item.provider, "_auth_type", "unknown")
            listing.append((str(auth_type), item.provider.__class__.__name__))
        return listing

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        for item in self._providers:
            provider = item.provider
            if await provider.supports(request.auth_type):
                print(
                    f"ProviderRegistry selected {provider.__class__.__name__}"
                    f" for auth_type={request.auth_type}",
                    file=sys.stderr,
                )
                return await provider.authenticate(request)
        raise AuthenticationError(f"No provider supports auth_type={request.auth_type}")
