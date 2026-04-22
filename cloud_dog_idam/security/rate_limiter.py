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

# cloud_dog_idam — Auth rate-limiter hooks
"""Sliding-window rate limiting with per-key lockout support."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass(slots=True)
class _RateState:
    hits: list[datetime] = field(default_factory=list)
    locked_until: datetime | None = None


class RateLimiter:
    """Represent rate limiter."""
    def __init__(
        self,
        *,
        limit: int = 5,
        window_seconds: int = 60,
        lockout_seconds: int = 300,
    ) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._lockout_seconds = lockout_seconds
        self._states: dict[str, _RateState] = {}

    def _state(self, key: str) -> _RateState:
        return self._states.setdefault(key, _RateState())

    def allow(self, key: str) -> bool:
        """Handle allow."""
        state = self._state(key)
        now = datetime.now(timezone.utc)
        if state.locked_until and now < state.locked_until:
            return False
        window_start = now - timedelta(seconds=self._window_seconds)
        state.hits = [hit for hit in state.hits if hit >= window_start]
        state.hits.append(now)
        if len(state.hits) > self._limit:
            state.locked_until = now + timedelta(seconds=self._lockout_seconds)
            return False
        return True

    def is_locked(self, key: str) -> bool:
        """Return whether locked."""
        state = self._states.get(key)
        if not state or not state.locked_until:
            return False
        return datetime.now(timezone.utc) < state.locked_until

    def unlock(self, key: str) -> None:
        """Handle unlock."""
        state = self._states.get(key)
        if state:
            state.locked_until = None
            state.hits.clear()
