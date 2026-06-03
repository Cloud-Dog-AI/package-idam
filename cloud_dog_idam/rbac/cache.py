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

# cloud_dog_idam — RBAC cache
"""Simple TTL cache for effective role and permission sets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(slots=True)
class _CacheEntry:
    value: set[str]
    expires_at: datetime


class RBACCache:
    """Represent r b a c cache."""
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._data: dict[str, _CacheEntry] = {}

    def get(self, key: str) -> set[str] | None:
        """Handle get."""
        entry = self._data.get(key)
        if entry is None:
            return None
        if datetime.now(timezone.utc) >= entry.expires_at:
            self._data.pop(key, None)
            return None
        return set(entry.value)

    def set(self, key: str, value: set[str]) -> None:
        """Handle set."""
        self._data[key] = _CacheEntry(
            value=set(value),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._ttl),
        )

    def invalidate(self, key: str | None = None) -> None:
        """Handle invalidate."""
        if key is None:
            self._data.clear()
            return
        self._data.pop(key, None)
