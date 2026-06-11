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

# cloud_dog_idam — Central secret-masking egress filter (W28A-741: IDAM-B2 §3.3)
"""Central secret-masking for non-admin response payloads (IDAM-B2 §3.3, §4.1 step 6).

PS-82 §7.2 hard rule: a non-admin caller must NEVER see a stored secret on any
surface. Secrets are ``client_secret``, ``refresh_token``, ``password``,
``access_key``, ``totp_secret``, ``backup_codes``, anything ending in
``_secret``/``_token``/``_key``, and the API-key reveal-once payload itself
(which is admin-only by separate path).

This module is the SHARED egress filter — services apply it ONCE in their
shared response path; no per-service fork. The filter is keyed by the
authenticated principal's effective role: admin (``"*"`` in flat_perms) sees
cleartext; everyone else gets ``"***REDACTED***"`` for secret-shaped fields.

W28A-741 G8 acceptance gate (c): a non-admin reading a profile/connection/
config payload that contains any of these fields gets the masked value on
**every surface** (API/MCP/A2A/WebUI) — coordinator-viewed live.
"""

from __future__ import annotations

from typing import Any

#: Whole-key matches (case-insensitive) considered secrets.
SECRET_KEY_TOKENS: frozenset[str] = frozenset({
    "client_secret",
    "refresh_token",
    "password",
    "passwd",
    "access_key",
    "secret",
    "private_key",
    "api_key",
    "apikey",
    "key_hash",
    "totp_secret",
    "backup_codes",
    "session_token",
    "bearer_token",
    "x-api-key",
    "authorization",
})

#: Suffix matches (case-insensitive) — any key ending in these is considered a secret.
SECRET_SUFFIX_TOKENS: frozenset[str] = frozenset({
    "_token",
    "_secret",
    "_key",
    "_password",
    "_credential",
    "_credentials",
})

#: Substitution value used for masked fields. Non-empty so the field is still
#: present in the payload (helps clients differentiate "field exists, you can't
#: see it" from "field absent"); see PS-82 §3.4 reveal-once contract.
REDACTED_PLACEHOLDER = "***REDACTED***"


def is_secret_key(name: str) -> bool:
    """Return whether a payload key name is considered a secret to be masked."""
    lname = name.lower() if isinstance(name, str) else ""
    if not lname:
        return False
    if lname in SECRET_KEY_TOKENS:
        return True
    return any(lname.endswith(suffix) for suffix in SECRET_SUFFIX_TOKENS)


def mask_secrets(payload: Any, *, is_admin: bool) -> Any:
    """Recursively redact secret-shaped fields in ``payload`` for non-admin callers.

    Returns ``payload`` unchanged when ``is_admin`` is True (admin sees
    cleartext — reveal-once still controls API-key generation separately). For
    non-admin: every dict key matching a secret token is replaced with
    ``REDACTED_PLACEHOLDER``; lists/tuples/dicts are recursed.

    The function is structure-preserving: a non-dict/non-list payload (str, int,
    bool, None) passes through unchanged regardless of admin state — the
    redaction is at the key level, not the value level (a top-level string can't
    be "the secret" because it has no associated key name).
    """
    if is_admin:
        return payload
    return _mask_recursive(payload)


def _mask_recursive(payload: Any) -> Any:
    """Inner recursion for ``mask_secrets`` with admin already known False."""
    if isinstance(payload, dict):
        return {
            k: (REDACTED_PLACEHOLDER if is_secret_key(str(k)) else _mask_recursive(v))
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [_mask_recursive(v) for v in payload]
    if isinstance(payload, tuple):
        return tuple(_mask_recursive(v) for v in payload)
    return payload
