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

# cloud_dog_idam — Token service interface
"""Unified token service interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cloud_dog_idam.domain.models import TokenPair


class TokenService(ABC):
    """Define token issuance and validation operations."""

    @abstractmethod
    def issue(self, user_id: str, claims: dict, ttl: int) -> TokenPair:
        """Issue a token pair for the user and claims."""
        raise NotImplementedError

    @abstractmethod
    def verify(self, token: str) -> dict:
        """Verify a token and return its claims."""
        raise NotImplementedError

    @abstractmethod
    def revoke(self, token_id: str) -> None:
        """Revoke a token by identifier."""
        raise NotImplementedError

    @abstractmethod
    def refresh(self, refresh_token: str) -> TokenPair:
        """Refresh an access token using a refresh token."""
        raise NotImplementedError
