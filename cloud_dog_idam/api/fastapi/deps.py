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
"""FastAPI auth dependencies for bearer + API-key + resource-aware authorisation.

W28A-741 (D-NO-BINDING-1 + IDAM-B2 §3.1 + §4.1 step 4):
  - NEW resource-aware ``require_permission(permission, *, resource_type=None,
    resource_id_param=None, engine, binding_repo, membership)`` form. Routes
    through the new ``cloud_dog_idam.rbac.grants.authorise`` resolver so the
    decision composes role-derived permissions with ``RBACBinding`` rows.
    Registers guard metadata so the ``AT1.N_NoUnguardedRoute`` meta-test can
    enumerate every protected route.
  - LEGACY positional ``require_permission(permission, rbac)`` form is KEPT as a
    thin shim (per W28A-741 coordinator answer Q3 — DO NOT remove). The shim
    calls the new resource-agnostic path with a ``DeprecationWarning`` so
    callers can migrate to the resource-aware form in W28A-742…751. Removing
    the positional form would break 8 services at once — unacceptable.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from fastapi import Depends, Header, HTTPException, Request

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.domain.models import User
from cloud_dog_idam.rbac.engine import RBACEngine
from cloud_dog_idam.tokens.jwt import JWTTokenService

if TYPE_CHECKING:
    from cloud_dog_idam.rbac.membership import MembershipResolver
    from cloud_dog_idam.storage.sqlalchemy.repositories import RBACBindingRepository


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


def require_permission(
    permission: str,
    rbac: RBACEngine | None = None,
    *,
    resource_type: str | None = None,
    resource_id_param: str | None = None,
    engine: RBACEngine | None = None,
    binding_repo: "RBACBindingRepository | None" = None,
    membership: "MembershipResolver | None" = None,
    route_path: str | None = None,
):
    """Build a FastAPI dependency that enforces ``permission`` (optionally on a resource).

    Two forms:

      **New (W28A-741) resource-aware form** — pass ``engine`` + ``binding_repo``
      + ``membership`` kwargs and (optionally) ``resource_type`` +
      ``resource_id_param``. Routes through ``cloud_dog_idam.rbac.grants.authorise``
      which composes role-derived permissions with ``RBACBinding`` rows on the
      user AND on every group the user is a member of (the cascade).

      **Legacy positional shim** — ``require_permission(permission, rbac)``
      delegates to a resource-agnostic ``rbac.has_permission(user_id, permission)``
      check and emits a ``DeprecationWarning``. Preserved per W28A-741
      coordinator answer Q3 so 8 services keep working until W28A-742…751
      migrate them. The shim path does NOT register guard metadata (because
      the route_path is not known at call time); migrating callers should pass
      ``engine=..., binding_repo=..., membership=...`` to get registration.

    Guard-metadata registration: if ``route_path`` is provided (preferred), the
    metadata is registered at decoration time so the no-unguarded-route
    meta-test can enumerate every guarded route. Callers that don't pass
    ``route_path`` (legacy / convenience) can still register manually via
    ``cloud_dog_idam.rbac.guard_registry.register_guard``.
    """
    # ---- Legacy positional shim ----
    if engine is None and binding_repo is None and membership is None:
        if rbac is None:
            raise TypeError(
                "require_permission requires either the legacy positional `rbac` "
                "argument OR the new resource-aware (engine, binding_repo, "
                "membership) kwargs (W28A-741: D-NO-BINDING-1)."
            )
        warnings.warn(
            "require_permission(permission, rbac) positional form is deprecated; "
            "pass engine=, binding_repo=, membership= for resource-aware "
            "authorisation. The legacy form is preserved (does a resource-agnostic "
            "rbac.has_permission check) but does not consult RBACBinding rows.",
            DeprecationWarning,
            stacklevel=2,
        )

        async def _legacy_dep(user: User = Depends(verify_bearer)) -> User:
            if not rbac.has_permission(user.user_id, permission):
                raise HTTPException(status_code=403, detail="Forbidden")
            return user

        return _legacy_dep

    # ---- New resource-aware form ----
    if engine is None or binding_repo is None or membership is None:
        raise TypeError(
            "Resource-aware require_permission requires all of: engine, "
            "binding_repo, membership."
        )

    # Register guard metadata for the no-unguarded-route meta-test (IDAM-B2 §3.2).
    if route_path is not None:
        # Lazy import: avoid circular at module load.
        from cloud_dog_idam.rbac.guard_registry import register_guard

        register_guard(
            route_path=route_path,
            permission=permission,
            resource_type=resource_type,
        )

    async def _resource_aware_dep(
        request: Request,
        user: User = Depends(verify_bearer),
    ) -> User:
        # Lazy import: avoid circular at module load.
        from cloud_dog_idam.rbac.grants import authorise as _authorise

        # Resolve resource_id from the path parameter if specified.
        rid: str | None = None
        if resource_id_param is not None:
            rid = request.path_params.get(resource_id_param)

        if not _authorise(
            user.user_id,
            permission=permission,
            resource_type=resource_type,
            resource_id=rid,
            engine=engine,
            binding_repo=binding_repo,
            membership=membership,
        ):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return _resource_aware_dep


def require_tenant(tenant_id: str):
    """Handle require tenant."""

    async def _dep(user: User = Depends(verify_bearer)) -> User:
        if user.tenant_id and user.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="Tenant mismatch")
        return user

    return _dep
