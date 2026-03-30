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


AuthScheme = Literal["bearer", "api_key", "any"]


class AuthContextMiddleware(BaseHTTPMiddleware):
    """Attach authenticated user context to request state."""

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
    ) -> None:
        super().__init__(app)
        self._token_service = token_service
        self._api_key_manager = api_key_manager
        self._rbac_engine = rbac_engine
        self._audit = audit_emitter
        self._skip_paths = skip_paths or {"/health", "/docs", "/openapi.json"}
        self._auth_scheme = auth_scheme

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

        if user is None:
            self._emit_auth_failure(request, "missing_credentials")
            return self._unauthorised("Authentication required")

        roles: set[str] = set()
        permissions: set[str] = set()
        if self._rbac_engine is not None:
            roles = self._rbac_engine.get_effective_roles(user.user_id)
            permissions = self._rbac_engine.get_effective_permissions(user.user_id)

        request.state.user = user
        request.state.user_id = user.user_id
        request.state.roles = roles
        request.state.permissions = permissions
        request.state.api_key = key_id
        return await call_next(request)
