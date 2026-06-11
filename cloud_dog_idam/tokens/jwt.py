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

# cloud_dog_idam — JWT token service
"""JWT issue/verify/revoke with refresh-token integration."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from cloud_dog_idam.domain.errors import TokenError
from cloud_dog_idam.domain.models import TokenPair
from cloud_dog_idam.tokens.base import TokenService
from cloud_dog_idam.tokens.refresh import RefreshTokenStore


class JWTTokenService(TokenService):
    """Represent j w t token service."""
    def __init__(
        self,
        *,
        secret: str | None = None,
        issuer: str = "cloud-dog",
        audience: str = "cloud-dog-services",
        algorithm: str = "HS256",
        access_ttl: int = 3600,
        refresh_ttl: int = 2_592_000,
    ) -> None:
        self._secret = secret or secrets.token_urlsafe(32)
        self._issuer = issuer
        self._audience = audience
        self._algorithm = algorithm
        self._access_ttl = access_ttl
        self._refresh = RefreshTokenStore(ttl_seconds=refresh_ttl, rotate_on_use=True)
        self._revoked_jti: set[str] = set()

    def issue(self, user_id: str, claims: dict, ttl: int | None = None) -> TokenPair:
        """Handle issue."""
        now = datetime.now(timezone.utc)
        effective_ttl = ttl or self._access_ttl
        jti = str(uuid4())
        payload = {
            "sub": user_id,
            "jti": jti,
            "iss": self._issuer,
            "aud": self._audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=effective_ttl)).timestamp()),
            **claims,
        }
        access = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        refresh = self._refresh.create(user_id)
        return TokenPair(
            access_token=access, refresh_token=refresh, expires_in=effective_ttl
        )

    def verify(self, token: str) -> dict:
        """Handle verify."""
        try:
            decoded = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
            )
        except Exception as exc:
            raise TokenError("Invalid JWT") from exc
        if decoded.get("jti") in self._revoked_jti:
            raise TokenError("Token revoked")
        return decoded

    def revoke(self, token_id: str) -> None:
        """Handle revoke."""
        self._revoked_jti.add(token_id)

    def refresh(self, refresh_token: str) -> TokenPair:
        """Handle refresh."""
        user_id, _ = self._refresh.consume(refresh_token)
        return self.issue(user_id, claims={})
