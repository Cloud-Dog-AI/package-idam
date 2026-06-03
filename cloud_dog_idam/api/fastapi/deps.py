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

# cloud_dog_idam — FastAPI dependencies
"""FastAPI auth dependencies for bearer and API-key protection."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.domain.models import User
from cloud_dog_idam.rbac.engine import RBACEngine
from cloud_dog_idam.tokens.jwt import JWTTokenService


async def verify_api_key(
    x_api_key: str | None = Header(default=None),
    key_manager: APIKeyManager | None = None,
) -> User:
    """Handle verify api key."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if key_manager is None:
        raise HTTPException(status_code=500, detail="API key manager unavailable")
    key = key_manager.validate(x_api_key)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return User(
        user_id=key.owner_user_id, username=key.owner_user_id, is_system_user=True
    )


async def verify_bearer(
    authorization: str | None = Header(default=None),
    token_service: JWTTokenService | None = None,
) -> User:
    """Handle verify bearer."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if token_service is None:
        raise HTTPException(status_code=500, detail="Token service unavailable")
    claims = token_service.verify(authorization.split(" ", 1)[1])
    return User(user_id=str(claims.get("sub", "")), username=str(claims.get("sub", "")))


def require_permission(permission: str, rbac: RBACEngine):
    """Handle require permission."""
    async def _dep(user: User = Depends(verify_bearer)) -> User:
        if not rbac.has_permission(user.user_id, permission):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return _dep


def require_tenant(tenant_id: str):
    """Handle require tenant."""
    async def _dep(user: User = Depends(verify_bearer)) -> User:
        if user.tenant_id and user.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="Tenant mismatch")
        return user

    return _dep
