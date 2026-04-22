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

# cloud_dog_idam — lightweight API-key-only provider
"""Minimal authentication provider for services using API keys only."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cloud_dog_idam.api_keys.hashing import hash_api_key
from cloud_dog_idam.domain.enums import UserStatus
from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, User
from cloud_dog_idam.providers.base import AuthProvider


class APIKeyOnlyProvider(AuthProvider):
    """Validate API keys using injected config mappings without full IDAM state."""

    _auth_type = "api_key_only"

    def __init__(
        self,
        *,
        key_role_mapping: Mapping[str, str] | None = None,
        key_hash_role_mapping: Mapping[str, str] | None = None,
        default_role: str = "viewer",
    ) -> None:
        self._default_role = default_role
        self._hash_to_role: dict[str, str] = {
            k: v for k, v in (key_hash_role_mapping or {}).items()
        }
        for raw_key, role in (key_role_mapping or {}).items():
            self._hash_to_role[hash_api_key(raw_key)] = role

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "APIKeyOnlyProvider":
        """Create provider from resolved config payload."""

        raw_mapping: dict[str, str] = {}
        for item in config.get("keys", []) or []:
            if isinstance(item, Mapping):
                key = str(item.get("key", ""))
                role = str(item.get("role", "viewer"))
                if key:
                    raw_mapping[key] = role
        hash_mapping = {
            str(key_hash): str(role)
            for key_hash, role in (config.get("key_hashes", {}) or {}).items()
        }
        return cls(
            key_role_mapping=raw_mapping,
            key_hash_role_mapping=hash_mapping,
            default_role=str(config.get("default_role", "viewer")),
        )

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type in {"api_key", "api_key_only"}

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        raw_key = request.secret or str(request.metadata.get("x_api_key", ""))
        if not raw_key:
            raise AuthenticationError("Missing API key")

        role = self._hash_to_role.get(hash_api_key(raw_key))
        if role is None:
            raise AuthenticationError("Invalid API key")

        key_fingerprint = hash_api_key(raw_key)[:12]
        principal = User(
            user_id=f"api-key:{key_fingerprint}",
            username=f"api-key:{key_fingerprint}",
            role=role or self._default_role,
            status=UserStatus.ACTIVE,
            is_system_user=True,
            email="",
        )
        return AuthResult(
            user=principal,
            claims={
                "auth_type": "api_key_only",
                "role": principal.role,
                "fingerprint": key_fingerprint,
            },
        )
