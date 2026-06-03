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

# cloud_dog_idam — Opaque token service
"""Server-side opaque token issue/verify/revoke."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

from cloud_dog_idam.domain.errors import TokenError
from cloud_dog_idam.domain.models import TokenPair
from cloud_dog_idam.tokens.base import TokenService
from cloud_dog_idam.tokens.refresh import RefreshTokenStore


@dataclass(slots=True)
class OpaqueTokenRecord:
    """Represent opaque token record."""
    token_id: str
    user_id: str
    claims: dict
    expires_at: datetime
    revoked: bool = False


class OpaqueTokenService(TokenService):
    """Represent opaque token service."""
    def __init__(self, *, access_ttl: int = 3600, refresh_ttl: int = 2_592_000) -> None:
        self._ttl = access_ttl
        self._refresh = RefreshTokenStore(ttl_seconds=refresh_ttl, rotate_on_use=True)
        self._records: dict[str, OpaqueTokenRecord] = {}

    def issue(self, user_id: str, claims: dict, ttl: int | None = None) -> TokenPair:
        """Handle issue."""
        token = secrets.token_urlsafe(48)
        token_id = str(uuid4())
        effective_ttl = ttl or self._ttl
        self._records[self._hash(token)] = OpaqueTokenRecord(
            token_id=token_id,
            user_id=user_id,
            claims=dict(claims),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=effective_ttl),
        )
        refresh = self._refresh.create(user_id)
        return TokenPair(
            access_token=token, refresh_token=refresh, expires_in=effective_ttl
        )

    def verify(self, token: str) -> dict:
        """Handle verify."""
        rec = self._records.get(self._hash(token))
        if rec is None or rec.revoked or rec.expires_at <= datetime.now(timezone.utc):
            raise TokenError("Opaque token invalid")
        return {"sub": rec.user_id, **rec.claims, "jti": rec.token_id}

    def revoke(self, token_id: str) -> None:
        """Handle revoke."""
        for rec in self._records.values():
            if rec.token_id == token_id:
                rec.revoked = True
                return

    def refresh(self, refresh_token: str) -> TokenPair:
        """Handle refresh."""
        user_id, _ = self._refresh.consume(refresh_token)
        return self.issue(user_id, claims={})

    @staticmethod
    def _hash(raw: str) -> str:
        return sha256(raw.encode("utf-8")).hexdigest()
