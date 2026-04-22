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

# cloud_dog_idam — API key lifecycle manager
"""Create, validate, rotate, revoke, and expire API keys."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cloud_dog_idam.api_keys.hashing import hash_api_key, key_matches
from cloud_dog_idam.domain.models import ApiKey


@dataclass(slots=True)
class APIKeyMetadata:
    """Represent a p i key metadata."""
    api_key_id: str
    owner_user_id: str
    key_prefix: str
    expires_at: datetime | None
    created_at: datetime


class APIKeyManager:
    """Represent a p i key manager."""
    def __init__(
        self, *, default_prefix: str = "cd_", overlap_seconds: int = 300
    ) -> None:
        self._prefix = default_prefix
        self._overlap_seconds = overlap_seconds
        self._keys: dict[str, ApiKey] = {}

    def generate(
        self,
        owner_id: str,
        *,
        ttl_days: int | None = None,
        key_prefix: str | None = None,
    ) -> tuple[str, APIKeyMetadata]:
        """Handle generate."""
        prefix = key_prefix or self._prefix
        raw = f"{prefix}{secrets.token_urlsafe(32)}"
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=ttl_days) if ttl_days else None
        item = ApiKey(
            api_key_id=str(uuid4()),
            owner_user_id=owner_id,
            key_prefix=prefix,
            key_hash=hash_api_key(raw),
            status="active",
            expires_at=expires,
        )
        self._keys[item.api_key_id] = item
        return raw, APIKeyMetadata(item.api_key_id, owner_id, prefix, expires, now)

    def validate(self, raw_key: str) -> ApiKey | None:
        """Handle validate."""
        now = datetime.now(timezone.utc)
        for item in self._keys.values():
            if item.status != "active":
                continue
            if item.expires_at and item.expires_at <= now:
                continue
            if key_matches(raw_key, item.key_hash):
                return item
        return None

    def rotate(self, key_id: str) -> tuple[str, APIKeyMetadata]:
        """Handle rotate."""
        if key_id not in self._keys:
            raise KeyError(key_id)
        current = self._keys[key_id]
        raw, meta = self.generate(current.owner_user_id, key_prefix=current.key_prefix)
        if current.expires_at is None:
            current.expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=self._overlap_seconds
            )
        current.status = "rotating"
        return raw, meta

    def revoke(self, key_id: str) -> bool:
        """Handle revoke."""
        item = self._keys.get(key_id)
        if item is None:
            return False
        item.status = "revoked"
        return True

    def list_keys(self, owner_id: str | None = None) -> list[ApiKey]:
        """List keys."""
        values = list(self._keys.values())
        if owner_id is None:
            return values
        return [k for k in values if k.owner_user_id == owner_id]
