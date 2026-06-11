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

# cloud_dog_idam — Guard metadata registry (W28A-741: IDAM-B2 §3.2)
"""Guard-metadata registry for the no-unguarded-route meta-test.

Every route that wires the new resource-aware ``require_permission`` guard
registers its metadata here at app-mount time. The
``AT1.N_NoUnguardedRoute`` meta-test enumerates every route on a representative
FastAPI app + every MCP tool + every A2A skill and asserts each is either
guard-registered OR present in the explicit ``PUBLIC_ALLOWLIST``. Anything else
is a **HARD FAIL** — the build-time / live equivalent of the IDAM-B2 §3.2
"meta-test that enumerates every route on every surface and asserts each one
declares + enforces a permission."

This is "no unguarded route" by structural detection rather than auditor
vigilance — the missing guard literally has no metadata entry.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GuardMetadata:
    """Metadata for a guarded route: which permission gates it + which resource_type (if any).

    A ``resource_type`` of ``None`` indicates a surface/feature gate (e.g.
    ``webui.access``). A non-``None`` ``resource_type`` indicates a
    resource-bearing gate (e.g. ``files.read`` on ``storage_profile``); in that
    case the route handler reads the actual ``resource_id`` from a path
    parameter.
    """

    permission: str
    resource_type: str | None = None


#: The explicit PUBLIC_ALLOWLIST per IDAM-B2 §3.2. Routes in this set are
#: intentionally unauthenticated. The set is intentionally TINY and reviewed:
#: adding to it is a coordinator-warranted decision. Per IDAM-B2 §3.2 verbatim:
#:   "/health, /ready, /live, /openapi.json, /docs, the login route,
#:    /a2a/.well-known/agent.json"
PUBLIC_ALLOWLIST: frozenset[str] = frozenset({
    "/health",
    "/ready",
    "/live",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",   # FastAPI auto-route for Swagger OAuth2 callback
    "/redoc",
    "/auth/login",
    "/auth/logout",
    "/auth/token/refresh",
    "/a2a/.well-known/agent.json",
})


#: Per-app guard registry. Keyed by route path; value is the GuardMetadata
#: registered by ``require_permission`` at decoration time.
#:
#: This is a module-level dict because FastAPI route decorators run at import
#: time, not at app instantiation. Test apps in the same process share this
#: registry; the no-unguarded-route meta-test takes a snapshot, enumerates
#: ``app.routes``, and asserts each app-route's path is in the registry or
#: PUBLIC_ALLOWLIST.
_REGISTRY: dict[str, GuardMetadata] = {}


def register_guard(
    *,
    route_path: str,
    permission: str,
    resource_type: str | None = None,
) -> None:
    """Record that ``route_path`` is gated by ``(permission, resource_type)``.

    Called by ``require_permission`` once per route (or once per ``Depends()``
    factory call when the route_path is provided). The meta-test queries this
    registry via ``is_route_guarded``.
    """
    _REGISTRY[route_path] = GuardMetadata(
        permission=permission, resource_type=resource_type,
    )


def get_guard(route_path: str) -> GuardMetadata | None:
    """Return the metadata registered for ``route_path``, or ``None`` if unguarded."""
    return _REGISTRY.get(route_path)


def is_route_guarded(route_path: str) -> bool:
    """Return True if ``route_path`` is either guard-registered OR in PUBLIC_ALLOWLIST.

    The no-unguarded-route meta-test asserts this returns True for every route
    in the enumerated app. False = HARD FAIL.
    """
    return route_path in _REGISTRY or route_path in PUBLIC_ALLOWLIST


def reset_registry() -> None:
    """Clear the in-process registry. **TEST USE ONLY.**

    The no-unguarded-route meta-test uses this between fixture-app builds so
    leftover registrations from a prior test don't leak. Production code MUST
    NOT call this.
    """
    _REGISTRY.clear()


def registered_routes() -> dict[str, GuardMetadata]:
    """Return a copy of the registry (for inspection / debugging / the meta-test)."""
    return dict(_REGISTRY)
