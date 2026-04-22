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

# cloud_dog_idam — Session primitives
"""Server-side session lifecycle management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4


@dataclass(slots=True)
class Session:
    """Represent session."""
    session_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: str = ""
    state: str = "initialising"
    data: dict = field(default_factory=dict)
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1)
    )


class SessionManager:
    """Represent session manager."""
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create(self, user_id: str, ttl_seconds: int = 3600) -> Session:
        """Handle create."""
        s = Session(
            user_id=user_id,
            state="active",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
        self._sessions[s.session_id] = s
        return s

    def end(self, session_id: str) -> bool:
        """Handle end."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.state = "ended"
        return True

    def get(self, session_id: str) -> Session | None:
        """Handle get."""
        return self._sessions.get(session_id)
