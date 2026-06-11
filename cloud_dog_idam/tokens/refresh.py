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

# cloud_dog_idam — Refresh token store
"""Refresh token lifecycle management."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(slots=True)
class RefreshTokenRecord:
    """Represent refresh token record."""
    token_hash: str
    user_id: str
    expires_at: datetime
    revoked: bool = False


class RefreshTokenStore:
    """Represent refresh token store."""
    def __init__(
        self, *, ttl_seconds: int = 2_592_000, rotate_on_use: bool = True
    ) -> None:
        self._ttl = ttl_seconds
        self._rotate = rotate_on_use
        self._store: dict[str, RefreshTokenRecord] = {}

    def create(self, user_id: str) -> str:
        """Handle create."""
        raw = secrets.token_urlsafe(48)
        self._store[self._hash(raw)] = RefreshTokenRecord(
            token_hash=self._hash(raw),
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._ttl),
        )
        return raw

    def consume(self, raw_token: str) -> tuple[str, bool]:
        """Handle consume."""
        token_hash = self._hash(raw_token)
        rec = self._store.get(token_hash)
        if rec is None or rec.revoked or rec.expires_at <= datetime.now(timezone.utc):
            raise ValueError("Invalid refresh token")
        if self._rotate:
            rec.revoked = True
            return rec.user_id, True
        return rec.user_id, False

    def revoke(self, raw_token: str) -> None:
        """Handle revoke."""
        token_hash = self._hash(raw_token)
        if token_hash in self._store:
            self._store[token_hash].revoked = True

    @staticmethod
    def _hash(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
