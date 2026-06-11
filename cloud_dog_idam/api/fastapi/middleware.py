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

# cloud_dog_idam — FastAPI auth middleware
"""Request authentication middleware for bearer and API-key schemes."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.audit.emitter import AuditEmitter
from cloud_dog_idam.audit.models import AuditEvent
from cloud_dog_idam.domain.models import User
from cloud_dog_idam.rbac.engine import RBACEngine
from cloud_dog_idam.tokens.jwt import JWTTokenService

if False:  # TYPE_CHECKING — avoid runtime import cycle
    from cloud_dog_idam.rbac.membership import MembershipResolver
    from cloud_dog_idam.storage.sqlalchemy.repositories import RBACBindingRepository


AuthScheme = Literal["bearer", "api_key", "any"]


class AuthContextMiddleware(BaseHTTPMiddleware):
    """Attach authenticated user context to request state.

    W28A-741 (IDAM-B2 §3.1 + §3.2):
      - ``skip_paths`` default expanded from ``{"/health","/docs","/openapi.json"}``
        to the canonical ``PUBLIC_ALLOWLIST`` from ``cloud_dog_idam.rbac.guard_registry``
        (adds ``/ready``, ``/live``, ``/redoc``, ``/auth/login``, ``/auth/logout``,
        ``/auth/token/refresh``, ``/a2a/.well-known/agent.json``). Callers can still
        override.
      - NEW optional ``binding_repo`` + ``membership`` constructor kwargs. When
        both are present alongside ``rbac_engine``, the middleware populates
        ``request.state.scoped_grants`` (the frozenset of ``(rt, rid, perm)``
        tuples) via the new ``cloud_dog_idam.rbac.grants.effective_grants``
        resolver. Routes that need resource-aware decisions read this directly
        OR Depends on the new ``require_permission(..., resource_type=...,
        resource_id_param=...)`` form.
    """

    def __init__(
        self,
        app,
        *,
        token_service: JWTTokenService | None = None,
        api_key_manager: APIKeyManager | None = None,
        rbac_engine: RBACEngine | None = None,
        audit_emitter: AuditEmitter | None = None,
        skip_paths: set[str] | None = None,
        auth_scheme: AuthScheme = "bearer",
        binding_repo: "RBACBindingRepository | None" = None,
        membership: "MembershipResolver | None" = None,
    ) -> None:
        super().__init__(app)
        self._token_service = token_service
        self._api_key_manager = api_key_manager
        self._rbac_engine = rbac_engine
        self._audit = audit_emitter
        # W28A-741: default skip_paths becomes the canonical PUBLIC_ALLOWLIST
        # (IDAM-B2 §3.2). Lazy import to avoid module-load cycle.
        if skip_paths is None:
            from cloud_dog_idam.rbac.guard_registry import PUBLIC_ALLOWLIST

            self._skip_paths = set(PUBLIC_ALLOWLIST)
        else:
            self._skip_paths = skip_paths
        self._auth_scheme = auth_scheme
        # W28A-741: optional resource-aware resolver wiring.
        self._binding_repo = binding_repo
        self._membership = membership

    def _emit_auth_failure(self, request: Request, reason: str) -> None:
        if self._audit is None:
            return
        self._audit.emit(
            AuditEvent(
                actor_id="anonymous",
                action="authenticate",
                outcome="failure",
                correlation_id=getattr(request.state, "correlation_id", ""),
                details={"reason": reason, "path": request.url.path},
            )
        )

    def _unauthorised(self, detail: str) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": detail})

    def _build_user_from_claims(self, claims: dict) -> User:
        sub = str(claims.get("sub", ""))
        return User(
            user_id=sub,
            username=sub,
            email=str(claims.get("email", "")),
            tenant_id=claims.get("tenant_id"),
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Handle dispatch."""
        request.state.correlation_id = request.headers.get(
            "x-request-id", request.headers.get("x-correlation-id", "")
        )
        if request.url.path in self._skip_paths:
            return await call_next(request)

        bearer_header = request.headers.get("authorization", "")
        api_key_header = request.headers.get("x-api-key", "")
        user: User | None = None
        key_id: str | None = None
        forwarded_principal: User | None = None

        can_try_bearer = self._auth_scheme in {"bearer", "any"}
        if can_try_bearer and bearer_header.lower().startswith("bearer "):
            if self._token_service is None:
                self._emit_auth_failure(request, "token_service_unavailable")
                return self._unauthorised("Bearer authentication unavailable")
            token = bearer_header.split(" ", 1)[1]
            try:
                claims = self._token_service.verify(token)
            except Exception:  # noqa: BLE001
                self._emit_auth_failure(request, "invalid_bearer_token")
                return self._unauthorised("Invalid bearer token")
            user = self._build_user_from_claims(claims)

        can_try_api_key = self._auth_scheme in {"api_key", "any"}
        if user is None and can_try_api_key and api_key_header:
            if self._api_key_manager is None:
                self._emit_auth_failure(request, "api_key_manager_unavailable")
                return self._unauthorised("API key authentication unavailable")
            key = self._api_key_manager.validate(api_key_header)
            if key is None:
                self._emit_auth_failure(request, "invalid_api_key")
                return self._unauthorised("Invalid API key")
            key_id = key.api_key_id
            user = User(
                user_id=key.owner_user_id,
                username=key.owner_user_id,
                is_system_user=True,
            )
            # PS-82 §8.3 — session-principal forwarding invariant.
            # The web-proxy authenticates the INTERNAL hop with its service/service-
            # admin key, but a user-originated request carries the forwarded session
            # principal (X-Request-Source: webui + X-Request-User/-Role). The backend
            # MUST authorise the REAL user, NOT collapse it to the service-key owner
            # (the W28A-890 / notification identity-collapse defect). We only trust
            # these headers on an already-API-key-authenticated internal hop.
            forwarded_principal = self._forwarded_principal(request)

        if user is None:
            self._emit_auth_failure(request, "missing_credentials")
            return self._unauthorised("Authentication required")

        # Forwarded session principal wins over the service-key owner for RBAC.
        effective = forwarded_principal or user

        roles: set[str] = set()
        permissions: set[str] = set()
        scoped_grants: frozenset[tuple[str, str, str]] = frozenset()
        if self._rbac_engine is not None:
            roles = self._rbac_engine.get_effective_roles(effective.user_id)
            permissions = self._rbac_engine.get_effective_permissions(effective.user_id)
            # W28A-741: populate scoped_grants via the new resolver when the
            # binding_repo + membership ports are wired. Routes that need
            # resource-aware decisions can read this directly OR Depends on
            # the new require_permission resource-aware form.
            if self._binding_repo is not None and self._membership is not None:
                from cloud_dog_idam.rbac.grants import effective_grants

                g = effective_grants(
                    effective.user_id,
                    engine=self._rbac_engine,
                    binding_repo=self._binding_repo,
                    membership=self._membership,
                )
                scoped_grants = g.scoped_grants

        request.state.user = effective
        request.state.user_id = effective.user_id
        request.state.roles = roles
        request.state.permissions = permissions
        request.state.scoped_grants = scoped_grants  # W28A-741: D-NO-BINDING-1
        request.state.api_key = key_id
        # Expose both identities for audit (who acted vs which key carried it).
        request.state.service_key_owner = user.user_id if forwarded_principal else None
        request.state.forwarded_principal = (
            forwarded_principal.user_id if forwarded_principal else None
        )
        return await call_next(request)

    @staticmethod
    def _forwarded_principal(request: Request) -> User | None:
        """Materialise the forwarded WebUI session principal, if present (PS-82 §8.3).

        Returns a ``User`` for the forwarded identity ONLY when the request is marked
        as a WebUI-originated internal hop (``X-Request-Source: webui``) AND carries a
        non-empty ``X-Request-User``. The forwarded role (``X-Request-Role``) is carried
        on the user so downstream RBAC seeding can use it; effective permissions are
        resolved from the RBAC engine on the forwarded user's id (never the service key).
        """
        source = str(request.headers.get("x-request-source", "")).strip().lower()
        if source != "webui":
            return None
        forwarded_user = str(request.headers.get("x-request-user", "")).strip()
        if not forwarded_user:
            return None
        forwarded_role = str(request.headers.get("x-request-role", "user")).strip().lower()
        principal = User(
            user_id=forwarded_user,
            username=forwarded_user,
            role=forwarded_role or "user",
        )
        return principal
