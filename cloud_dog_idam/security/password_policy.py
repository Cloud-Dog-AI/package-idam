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

# cloud_dog_idam — Password policy checks
"""Password complexity, history, banned-list, and expiry enforcement."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cloud_dog_idam.config.models import PasswordPolicyConfig


@dataclass(slots=True)
class PasswordValidationResult:
    """Represent password validation result."""
    valid: bool
    reasons: list[str] = field(default_factory=list)


class PasswordPolicy:
    """Represent password policy."""
    def __init__(
        self,
        config: PasswordPolicyConfig,
        *,
        history_depth: int = 5,
        banned_passwords: set[str] | None = None,
        max_age_days: int | None = None,
    ) -> None:
        self._config = config
        self._history_depth = history_depth
        self._banned = {p.lower() for p in (banned_passwords or set())}
        self._max_age_days = max_age_days

    @staticmethod
    def hash_password(password: str) -> str:
        """Handle hash password."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def validate(self, password: str) -> tuple[bool, str]:
        """Handle validate."""
        result = self.validate_password(password, [], None)
        if result.valid:
            return True, "ok"
        return False, "; ".join(result.reasons)

    def validate_password(
        self,
        password: str,
        password_history_hashes: list[str],
        last_changed_at: datetime | None,
    ) -> PasswordValidationResult:
        """Validate password."""
        reasons: list[str] = []
        if len(password) < self._config.min_length:
            reasons.append("Password too short")
        if self._config.require_uppercase and not re.search(r"[A-Z]", password):
            reasons.append("Missing uppercase letter")
        if self._config.require_lowercase and not re.search(r"[a-z]", password):
            reasons.append("Missing lowercase letter")
        if self._config.require_digit and not re.search(r"[0-9]", password):
            reasons.append("Missing digit")
        if self._config.require_special and not re.search(r"[^A-Za-z0-9]", password):
            reasons.append("Missing special character")

        if password.lower() in self._banned:
            reasons.append("Password is in banned list")

        hashed = self.hash_password(password)
        if hashed in password_history_hashes[: self._history_depth]:
            reasons.append("Password reused from history")

        if self._max_age_days is not None and last_changed_at is not None:
            expiry = last_changed_at + timedelta(days=self._max_age_days)
            if datetime.now(timezone.utc) > expiry:
                reasons.append("Password expired")

        return PasswordValidationResult(valid=not reasons, reasons=reasons)
