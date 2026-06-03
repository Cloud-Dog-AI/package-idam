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

# cloud_dog_idam — Conformance tests
"""Reusable conformance checks for service integrations.

Consuming projects import and call these checks in CI to verify
correct IDAM integration per FR1.30.
"""

from __future__ import annotations

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.rbac.engine import RBACEngine
from cloud_dog_idam.tokens.base import TokenService


def check_default_deny(rbac: RBACEngine, user_id: str) -> bool:
    """Verify that an unprivileged user has no admin permissions."""
    return not rbac.has_permission(user_id, "admin:write")


def check_api_key_hash_only(manager: APIKeyManager) -> bool:
    """Verify API keys are returned raw once and stored hash-only."""
    raw_key, metadata = manager.generate(owner_id="conformance-test")
    assert raw_key, "generate() must return a non-empty raw key"
    stored = manager.validate(raw_key)
    assert stored is not None, "validate() must resolve a generated key"
    assert not hasattr(stored, "raw_key"), "Stored key must not expose raw key values"
    assert stored.key_hash and stored.key_hash != raw_key
    assert manager.revoke(metadata.api_key_id) is True
    return True


def check_token_issue_verify_revoke(token_service: TokenService, user_id: str) -> bool:
    """Verify issue -> verify -> revoke behaviour."""
    pair = token_service.issue(user_id=user_id, claims={"role": "user"}, ttl=300)
    assert pair.access_token, "issue() must return an access token"
    principal = token_service.verify(pair.access_token)
    assert principal.get("sub") == user_id, "verify() must return the correct subject"
    token_id = principal.get("jti")
    assert token_id, "verified token must contain jti for revocation"
    token_service.revoke(str(token_id))
    revoked = False
    try:
        token_service.verify(pair.access_token)
    except Exception:  # noqa: BLE001
        revoked = True
    assert revoked, "verify() must fail after token revocation"
    return True


def check_rbac_role_inheritance(rbac: RBACEngine, admin_user_id: str) -> bool:
    """Verify that admin role grants admin permissions."""
    assert rbac.has_permission(admin_user_id, "admin:write"), (
        "Admin user must have admin:write permission"
    )
    return True


def run_all_conformance_checks(
    rbac: RBACEngine,
    token_service: TokenService,
    api_key_manager: APIKeyManager,
    unprivileged_user_id: str,
    admin_user_id: str,
) -> dict[str, bool]:
    """Run all conformance checks and return check_name -> result."""
    results: dict[str, bool] = {}
    results["default_deny"] = check_default_deny(rbac, unprivileged_user_id)
    results["api_key_hash_only"] = check_api_key_hash_only(api_key_manager)
    results["token_lifecycle"] = check_token_issue_verify_revoke(
        token_service, unprivileged_user_id
    )
    results["rbac_inheritance"] = check_rbac_role_inheritance(rbac, admin_user_id)
    return results
