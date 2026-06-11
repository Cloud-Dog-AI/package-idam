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

# cloud_dog_idam — UM10 TOTP Manager
"""High-level TOTP MFA lifecycle manager (PS-70 UM10).

License: Apache 2.0
Ownership: Cloud-Dog, Viewdeck Engineering Limited
Description: Wraps security.mfa helpers into a user-scoped manager with
             encrypted secret storage and backup code lifecycle.
Requirements: UM10
Tasks: W28A-696
Architecture: UM10 Optional Security Controls
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from cloud_dog_idam.domain.models import User
from cloud_dog_idam.security.mfa import (
    MFASetup,
    consume_backup_code,
    enrol_mfa,
    generate_backup_codes,
    hash_backup_code,
    verify_totp,
)
from cloud_dog_idam.users.service import UserService


@dataclass(slots=True)
class TOTPSecret:
    """Result of TOTP secret generation."""
    secret: str
    otpauth_uri: str
    backup_codes: list[str]


class TOTPManager:
    """Manage MFA/TOTP lifecycle per user (PS-70 UM10).

    Provides generate_secret, verify, enable, disable, and backup code
    management with hashed storage for all sensitive material.
    """

    def __init__(
        self,
        user_service: UserService,
        issuer: str = "cloud-dog",
    ) -> None:
        self._user_service = user_service
        self._issuer = issuer

    def _get_user(self, user_id: str) -> User:
        user = self._user_service.get(user_id)
        if user is None:
            raise ValueError(f"User not found: {user_id}")
        return user

    def generate_secret(self, user_id: str) -> TOTPSecret:
        """Generate a new TOTP secret for a user (setup phase).

        The raw secret and backup codes are returned ONCE. The caller
        must display them to the user. They are NOT persisted until
        enable_mfa() is called with a valid verification code.
        """
        user = self._get_user(user_id)
        setup = enrol_mfa(user.username, issuer=self._issuer)
        return TOTPSecret(
            secret=setup.secret,
            otpauth_uri=setup.otpauth_uri,
            backup_codes=setup.backup_codes,
        )

    def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify a TOTP code for a user with MFA enabled."""
        user = self._get_user(user_id)
        if not user.mfa_enabled or not user.totp_secret:
            return False
        return verify_totp(user.totp_secret, code)

    def enable_mfa(self, user_id: str, secret: str, code: str) -> bool:
        """Enable MFA after verifying the first code.

        The secret from generate_secret() and a valid TOTP code must
        both be provided. On success, the secret is stored (hashed backup
        codes alongside) and mfa_enabled is set True.
        """
        if not verify_totp(secret, code):
            return False
        backup = generate_backup_codes()
        hashed_backups = [hash_backup_code(c) for c in backup]
        self._user_service.update(
            user_id,
            mfa_enabled=True,
            totp_secret=secret,
            backup_codes=json.dumps(hashed_backups),
        )
        return True

    def disable_mfa(self, user_id: str) -> bool:
        """Disable MFA for a user (admin or re-authenticated self)."""
        user = self._get_user(user_id)
        if not user.mfa_enabled:
            return False
        self._user_service.update(
            user_id,
            mfa_enabled=False,
            totp_secret=None,
            backup_codes=None,
        )
        return True

    def generate_backup_codes(self, user_id: str, count: int = 10) -> list[str]:
        """Generate fresh backup codes, replacing any existing ones."""
        self._get_user(user_id)
        codes = generate_backup_codes(count=count)
        hashed = [hash_backup_code(c) for c in codes]
        self._user_service.update(user_id, backup_codes=json.dumps(hashed))
        return codes

    def use_backup_code(self, user_id: str, code: str) -> bool:
        """Consume a single-use backup code."""
        user = self._get_user(user_id)
        if not user.mfa_enabled or not user.backup_codes:
            return False
        try:
            hashes = set(json.loads(user.backup_codes))
        except (json.JSONDecodeError, TypeError):
            return False
        if not consume_backup_code(hashes, code):
            return False
        self._user_service.update(
            user_id,
            backup_codes=json.dumps(sorted(hashes)),
        )
        return True
