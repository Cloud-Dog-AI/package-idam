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

# cloud_dog_idam — MFA/TOTP helpers
"""TOTP enrolment, verification, backup codes, and recovery helpers."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass

try:
    import pyotp  # type: ignore
except ImportError:  # pragma: no cover
    pyotp = None


@dataclass(slots=True)
class MFASetup:
    """Represent m f a setup."""
    secret: str
    otpauth_uri: str
    backup_codes: list[str]


def generate_totp_secret() -> str:
    """Handle generate totp secret."""
    if pyotp:
        return pyotp.random_base32()
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def generate_backup_codes(count: int = 10) -> list[str]:
    """Handle generate backup codes."""
    return [secrets.token_hex(4) for _ in range(count)]


def hash_backup_code(code: str) -> str:
    """Handle hash backup code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def enrol_mfa(username: str, issuer: str = "cloud-dog") -> MFASetup:
    """Handle enrol mfa."""
    secret = generate_totp_secret()
    if pyotp:
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    else:
        uri = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"
    return MFASetup(
        secret=secret, otpauth_uri=uri, backup_codes=generate_backup_codes()
    )


def verify_totp(secret: str, code: str) -> bool:
    """Handle verify totp."""
    if pyotp is None:
        return False
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


def consume_backup_code(backup_hashes: set[str], code: str) -> bool:
    """Handle consume backup code."""
    hashed = hash_backup_code(code)
    if hashed not in backup_hashes:
        return False
    backup_hashes.remove(hashed)
    return True
