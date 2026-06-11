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

# cloud_dog_idam — Config models
"""Typed config models for IDAM runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class PasswordPolicyConfig:
    """Represent password policy config."""
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    max_failed_attempts: int = 5
    lockout_duration: int = 900


@dataclass(frozen=True, slots=True)
class TokenConfig:
    """Represent token config."""
    algorithm: str = "HS256"
    access_ttl: int = 3600
    refresh_ttl: int = 2_592_000


@dataclass(frozen=True, slots=True)
class IDAMConfig:
    """Represent i d a m config."""
    auth_mode: str = "local"
    session_timeout: int = 3600
    api_key_max_age_days: int = 90
    rbac_cache_ttl: int = 300
    password_policy: PasswordPolicyConfig = field(default_factory=PasswordPolicyConfig)
    token: TokenConfig = field(default_factory=TokenConfig)


def idam_config_from_dict(raw: dict[str, Any]) -> IDAMConfig:
    """Handle idam config from dict."""
    auth = raw.get("auth", {}) if isinstance(raw, dict) else {}
    rbac = raw.get("rbac", {}) if isinstance(raw, dict) else {}
    tokens = (
        (raw.get("tokens", {}) or {}).get("jwt", {}) if isinstance(raw, dict) else {}
    )
    pp = raw.get("password_policy", {}) if isinstance(raw, dict) else {}

    return IDAMConfig(
        auth_mode=str(auth.get("mode", "local")),
        session_timeout=int(auth.get("session_timeout", 3600) or 3600),
        api_key_max_age_days=int(auth.get("api_key_max_age", 90) or 90),
        rbac_cache_ttl=int(rbac.get("cache_ttl", 300) or 300),
        password_policy=PasswordPolicyConfig(
            min_length=int(pp.get("min_length", 12) or 12),
            require_uppercase=bool(pp.get("require_uppercase", True)),
            require_lowercase=bool(pp.get("require_lowercase", True)),
            require_digit=bool(pp.get("require_digit", True)),
            require_special=bool(pp.get("require_special", True)),
            max_failed_attempts=int(pp.get("max_failed_attempts", 5) or 5),
            lockout_duration=int(pp.get("lockout_duration", 900) or 900),
        ),
        token=TokenConfig(
            algorithm=str(tokens.get("algorithm", "HS256")),
            access_ttl=int(tokens.get("access_ttl", 3600) or 3600),
            refresh_ttl=int(tokens.get("refresh_ttl", 2_592_000) or 2_592_000),
        ),
    )
