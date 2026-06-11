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

# cloud_dog_idam — RBAC engine
"""Compute effective roles and permissions.

W28A-741 (D-NO-BASELINE-1 fix):
  - ``__init__`` ALWAYS starts from ``BASELINE_ROLE_PERMISSIONS`` and merges the
    caller's ``role_overlay=`` dict on top (per-role union). The legacy
    ``role_permissions=`` kwarg is preserved as a deprecated positional/keyword
    SHIM (per W28A-741 coordinator answer Q3 — DO NOT remove; 8 services still
    pass it). The shim merges the caller's dict the same way as ``role_overlay``
    (NOT a full replacement as before) and emits a ``DeprecationWarning`` so
    callers can migrate to ``role_overlay`` in W28A-742…751.

W28A-741 (D-NO-BINDING-1 fix support):
  - ``_invalidate_user`` now also drops the ``grants:{user_id}`` cache key the
    new ``cloud_dog_idam.rbac.grants`` resolver uses, so add/remove-member
    invalidates the scoped-grant cache within one request (live revoke). The
    cascade-test STEP 5 (remove U from G → 403, no restart) depends on this.
"""

from __future__ import annotations

import warnings

from cloud_dog_idam.rbac.cache import RBACCache


class RBACEngine:
    """Represent r b a c engine."""

    def __init__(
        self,
        *,
        role_overlay: dict[str, set[str]] | None = None,
        cache_ttl_seconds: int = 300,
        role_permissions: dict[str, set[str]] | None = None,
    ) -> None:
        """Build the engine with the canonical baseline + an optional per-service overlay.

        Args:
            role_overlay: NEW preferred kwarg (W28A-741). Per-service role →
                permission overlay; merged on top of ``BASELINE_ROLE_PERMISSIONS``
                via per-role union. Caller's overlay can only ADD permissions to
                a role or define a new role; it can NEVER erase a baseline
                permission. This is the D-NO-BASELINE-1 fix — baseline grants
                survive per-service customisation.
            cache_ttl_seconds: TTL for the role/permission/grants cache.
            role_permissions: DEPRECATED back-compat kwarg (kept per W28A-741
                coord answer Q3 — 8 services still use it). Merged as overlay
                (same as ``role_overlay=``) with a ``DeprecationWarning``. Set
                only one of ``role_overlay`` and ``role_permissions``; if both,
                ``role_overlay`` wins.
        """
        self._user_roles: dict[str, set[str]] = {}
        self._group_memberships: dict[str, set[str]] = {}
        self._group_roles: dict[str, set[str]] = {}
        # Canonical baseline + per-service overlay. Imported lazily to avoid a
        # hard import cycle at module load.
        from cloud_dog_idam.rbac.role_catalog import BASELINE_ROLE_PERMISSIONS

        composed: dict[str, set[str]] = {
            name: set(perms) for name, perms in BASELINE_ROLE_PERMISSIONS.items()
        }

        # Prefer role_overlay; fall back to deprecated role_permissions.
        overlay: dict[str, set[str]] | None = None
        if role_overlay is not None:
            overlay = role_overlay
        elif role_permissions is not None:
            warnings.warn(
                "RBACEngine(role_permissions=...) is deprecated; pass "
                "role_overlay=... instead. The supplied dict will be MERGED with "
                "the PS-82 §7.2 BASELINE_ROLE_PERMISSIONS (per-role union), not "
                "used as a full replacement (W28A-741: D-NO-BASELINE-1).",
                DeprecationWarning,
                stacklevel=2,
            )
            overlay = role_permissions

        if overlay:
            for name, perms in overlay.items():
                composed.setdefault(name, set()).update(set(perms))

        self._role_permissions = composed
        self._cache = RBACCache(ttl_seconds=cache_ttl_seconds)

    def _invalidate_user(self, user_id: str) -> None:
        """Invalidate the cached roles AND permissions AND scoped grants for a user.

        W28A-820 fix: effective roles/permissions are cached under the prefixed
        keys ``roles:{user_id}`` / ``perms:{user_id}`` (see get_effective_*),
        so invalidating the bare ``user_id`` key left the real entries stale
        until TTL — role/group changes (membership propagation, downgrades)
        did not take effect promptly.

        **W28A-741 extension:** also drops ``grants:{user_id}`` — the new
        scoped-grant cache key used by ``cloud_dog_idam.rbac.grants.effective_grants``.
        Without this, the cascade STEP 5 (remove U from G → 403) would NOT be
        live — the resolver would return the stale ``RBACBinding`` set from G
        until the TTL expired. The cascade test asserts the live revoke.
        """
        self._cache.invalidate(f"roles:{user_id}")
        self._cache.invalidate(f"perms:{user_id}")
        self._cache.invalidate(f"grants:{user_id}")   # W28A-741: scoped-grants cache

    def assign_role_to_user(self, user_id: str, role: str) -> None:
        """Handle assign role to user."""
        self._user_roles.setdefault(user_id, set()).add(role)
        self._invalidate_user(user_id)

    def add_user_to_group(self, user_id: str, group_id: str) -> None:
        """Handle add user to group."""
        self._group_memberships.setdefault(user_id, set()).add(group_id)
        self._invalidate_user(user_id)

    def remove_user_from_group(self, user_id: str, group_id: str) -> None:
        """Remove a user from a group (W28A-741: the cascade STEP 5 live-revoke path).

        Mirrors ``add_user_to_group``. Calling this MUST invalidate the user's
        scoped-grants cache so the next ``authorise(...)`` call sees the new
        (smaller) grant set without waiting for the TTL.
        """
        groups = self._group_memberships.get(user_id)
        if groups is not None:
            groups.discard(group_id)
        self._invalidate_user(user_id)

    def assign_role_to_group(self, group_id: str, role: str) -> None:
        """Handle assign role to group."""
        self._group_roles.setdefault(group_id, set()).add(role)
        for uid, groups in self._group_memberships.items():
            if group_id in groups:
                self._invalidate_user(uid)

    def get_effective_roles(self, user_id: str) -> set[str]:
        """Return effective roles."""
        cached = self._cache.get(f"roles:{user_id}")
        if cached is not None:
            return cached
        roles = set(self._user_roles.get(user_id, set()))
        for group_id in self._group_memberships.get(user_id, set()):
            roles.update(self._group_roles.get(group_id, set()))
        self._cache.set(f"roles:{user_id}", roles)
        return roles

    def get_effective_permissions(self, user_id: str) -> set[str]:
        """Return effective permissions."""
        cached = self._cache.get(f"perms:{user_id}")
        if cached is not None:
            return cached
        permissions: set[str] = set()
        for role in self.get_effective_roles(user_id):
            permissions.update(self._role_permissions.get(role, set()))
        self._cache.set(f"perms:{user_id}", permissions)
        return permissions

    def has_permission(self, user_id: str, permission: str) -> bool:
        """Return whether this has permission."""
        perms = self.get_effective_permissions(user_id)
        return permission in perms or "*" in perms

    def authorise(self, user_id: str, resource: str, action: str) -> bool:
        """Resource-agnostic legacy authorise.

        For RESOURCE-AWARE authorisation (the W28A-741 resolver), use
        ``cloud_dog_idam.rbac.grants.authorise(user_id, permission=...,
        resource_type=..., resource_id=...)`` — which composes role-derived
        permissions with ``RBACBinding`` rows for the user AND for each group
        the user is a member of. This legacy method is preserved for callers
        that gate on a resource-agnostic permission string only.
        """
        return self.has_permission(user_id, f"{resource}:{action}")
