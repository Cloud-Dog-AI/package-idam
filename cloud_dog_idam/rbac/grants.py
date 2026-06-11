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

# cloud_dog_idam — Effective-grants resolver (W28A-741: D-NO-BINDING-1 fix)
"""Resource-aware authorization resolver — the keystone (IDAM-B2 §2.2).

This module is the W28A-741 keystone fix for **D-NO-BINDING-1** (PS-83 §5): the
``RBACBinding`` model + ``RBACBindingRepository.by_subject`` exist estate-wide
but have NEVER been consulted at authorization time. ``RBACEngine`` is purely
``role → permission``; it has no ``resource_id`` parameter. The cascade
(group-admin adds U to G → U accesses G's resource → remove U → revoked) has
no data path today.

This module closes the loop by COMPOSING:

  flat_perms     := engine.get_effective_permissions(user_id)   # role-derived (existing)
  scoped_grants  := { (rt, rid, perm) for each RBACBinding row of:
                        - subject_type='user',  subject_id=user_id
                        - subject_type='group', subject_id ∈ membership.groups_of(user_id)
                    }

…and the resource-aware decision function::

  authorise(user_id, *, permission, resource_type=None, resource_id=None) -> bool

with strict default-DENY semantics (PS-82 §3.1; AGENT-LESSONS §6.81 — "pre-existing"
is not an escape; if the failing code is in your repo, fix it).

**Cascade semantics proven by construction** (IDAM-B2 §2.2):
  - **add U to G** → ``GroupMember(U,G)`` row inserted → next ``effective_grants(U)``
    call returns G's bindings → U authorised for the bound resource.
  - **U reads P** → ``authorise(U, permission=files.read,
    resource_type=storage_profile, resource_id=P)`` → True via G's binding;
    ``resource_id=other`` → False (default-DENY).
  - **remove U from G** → ``GroupMember(U,G)`` deleted → ``_invalidate_user``
    drops ``grants:{uid}`` cache key → next call 403. **Revocation is automatic**
    because the binding lives on the GROUP, not copied onto the user.

The live-revoke transition (STEP 5 of the T3-<svc>-CASCADE test) is what proves
the keystone works — per coordinator's W28A-741 approval note, the cascade-test
trace MUST be tag-reachable.

**Cache key encoding (W28A-741 C3 — coordinator constraint).** The
``grants:{user_id}`` cache stores the scoped grant set serialised into the
``RBACCache`` ``set[str]`` storage. Each grant tuple ``(rt, rid, perm)`` is
encoded with the **ASCII Unit Separator** ``\\x1f`` (U+001F) as the field
delimiter — chosen because it cannot legally appear in a ``resource_id``,
``resource_type``, or ``permission`` string (it is a non-printing control
character outside the canonical permission charset ``[A-Za-z0-9._:*-]`` and
typical resource id charset). Decoding splits on ``\\x1f`` and reconstructs the
tuple. The test ``AT1.N_CascadeResolves`` asserts that a resource_id containing
``|`` (pipe) is round-trip safe under this encoding (proving the C3 constraint
that the old ``|`` delimiter would have been collision-unsafe).

Owned by ``cloud_dog_idam``. Per-service services consume via the resource-aware
``cloud_dog_idam.api.fastapi.deps.require_permission`` guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_dog_idam.rbac.engine import RBACEngine
    from cloud_dog_idam.storage.sqlalchemy.repositories import RBACBindingRepository


# --- Cache key encoding (W28A-741 C3 binding constraint) --------------------------
#: ASCII Unit Separator (U+001F) — used to serialise ``(rt, rid, perm)`` tuples
#: into the existing ``RBACCache`` ``set[str]`` storage. CANNOT collide with any
#: legal resource_id/resource_type/permission character (control character outside
#: the canonical charset).
GRANT_TUPLE_DELIM = "\x1f"


def encode_grant_tuple(resource_type: str, resource_id: str, permission: str) -> str:
    """Encode a scoped-grant tuple for ``RBACCache`` storage (W28A-741 C3)."""
    return f"{resource_type}{GRANT_TUPLE_DELIM}{resource_id}{GRANT_TUPLE_DELIM}{permission}"


def decode_grant_tuple(encoded: str) -> tuple[str, str, str] | None:
    """Decode a cached grant string back to ``(rt, rid, perm)`` or ``None`` if malformed."""
    parts = encoded.split(GRANT_TUPLE_DELIM)
    if len(parts) != 3:
        return None
    return (parts[0], parts[1], parts[2])


# --- Membership port (IDAM-B2 §4.1 step 2) ----------------------------------------
# Imported from ``cloud_dog_idam.rbac.membership`` for type-only use here; the
# Protocol itself lives in ``membership.py`` to avoid a circular import.
class MembershipResolverProto(Protocol):
    """Thin Protocol re-declared here for type-checker sanity (see membership.py)."""

    def groups_of(self, user_id: str) -> set[str]: ...


# --- Resolved-grants container ---------------------------------------------------
@dataclass(frozen=True, slots=True)
class ResolvedGrants:
    """Composed effective grants for a principal (IDAM-B2 §2.2 ``effective_grants`` return).

    ``flat_perms`` are the resource-agnostic role-derived permissions (today's
    path — unchanged). Includes wildcard ``*`` for admin.

    ``scoped_grants`` are the resource-aware grants composed from
    ``RBACBinding`` rows for the user AND for every group the user is a member
    of. Each tuple is ``(resource_type, resource_id, permission)`` where
    ``resource_id`` may be ``"*"`` (any resource of this type in the project).
    """

    flat_perms: frozenset[str]
    scoped_grants: frozenset[tuple[str, str, str]]


# --- The resolver (IDAM-B2 §2.2) -------------------------------------------------
def effective_grants(
    user_id: str,
    *,
    engine: "RBACEngine",
    binding_repo: "RBACBindingRepository",
    membership: MembershipResolverProto,
) -> ResolvedGrants:
    """Compose flat permissions (role-derived) with scoped grants (binding-derived).

    Cache: a ``ResolvedGrants`` is cached on ``engine._cache`` under
    ``grants:{user_id}``. The cache stores the FLAT permission set and the
    scoped-grant set serialised with ``GRANT_TUPLE_DELIM`` (W28A-741 C3). The
    cache is invalidated by ``engine._invalidate_user`` which also drops
    ``roles:{uid}`` and ``perms:{uid}`` — extension added in W28A-741 so
    membership changes (add/remove-member) take effect within one request
    (live revoke).
    """
    # Try cached scoped grants. RBACCache stores set[str], so we round-trip
    # through encode/decode.
    cached_encoded = engine._cache.get(f"grants:{user_id}")
    if cached_encoded is not None:
        decoded: set[tuple[str, str, str]] = set()
        for s in cached_encoded:
            t = decode_grant_tuple(s)
            if t is not None:
                decoded.add(t)
        flat = frozenset(engine.get_effective_permissions(user_id))
        return ResolvedGrants(flat_perms=flat, scoped_grants=frozenset(decoded))

    # Compute fresh.
    flat = frozenset(engine.get_effective_permissions(user_id))
    binding_rows = list(binding_repo.by_subject("user", user_id))
    for group_id in membership.groups_of(user_id):
        binding_rows.extend(binding_repo.by_subject("group", group_id))

    scoped: set[tuple[str, str, str]] = set()
    for row in binding_rows:
        rt = str(getattr(row, "resource_type", ""))
        rid = str(getattr(row, "resource_id", "*") or "*")
        perm = str(getattr(row, "permission", ""))
        if rt and perm:
            scoped.add((rt, rid, perm))

    # Cache (serialised).
    engine._cache.set(
        f"grants:{user_id}",
        {encode_grant_tuple(rt, rid, perm) for (rt, rid, perm) in scoped},
    )

    return ResolvedGrants(flat_perms=flat, scoped_grants=frozenset(scoped))


def authorise(
    user_id: str,
    *,
    permission: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    engine: "RBACEngine",
    binding_repo: "RBACBindingRepository",
    membership: MembershipResolverProto,
) -> bool:
    """Return whether ``user_id`` is authorised for ``(permission, resource_type, resource_id)``.

    Default-DENY semantics (PS-82 §3.1):
      - admin wildcard ``*`` in flat perms → ALLOW (short-circuit).
      - resource-agnostic check (``resource_type is None``) → ALLOW iff ``permission``
        is in ``flat_perms``.
      - resource-bearing check → ALLOW iff a scoped grant ``(rt, rid, perm)`` exists
        where ``rt == resource_type`` AND ``perm == permission`` AND
        ``rid in (resource_id, "*")``.
      - fallback: a role-level resource-agnostic grant of the same permission also
        ALLOWs (e.g. ``files.read`` granted to all members of a role with no
        resource constraint) — this preserves backward-compat with role-only
        services that haven't migrated to scoped bindings yet (D-NO-BASELINE-1
        is the migration path).
      - otherwise DENY.
    """
    g = effective_grants(
        user_id, engine=engine, binding_repo=binding_repo, membership=membership,
    )
    # Admin wildcard short-circuit.
    if "*" in g.flat_perms:
        return True
    # Resource-agnostic gate (surface/feature check, e.g. ``webui.access``).
    if resource_type is None:
        return permission in g.flat_perms
    # Resource-bearing gate: scoped binding must match.
    for (rt, rid, perm) in g.scoped_grants:
        if rt == resource_type and perm == permission and rid in (resource_id, "*"):
            return True
    # Role-level resource-agnostic fallback (e.g. a role carries ``files.read``
    # without a binding — used by services pre-migration; this is the surface
    # that D-NO-BASELINE-1 ensures NEVER LOSES the baseline grants).
    return permission in g.flat_perms


def allowed_resource_ids(
    user_id: str,
    resource_type: str,
    permission: str,
    *,
    engine: "RBACEngine",
    binding_repo: "RBACBindingRepository",
    membership: MembershipResolverProto,
) -> set[str]:
    """Return the set of ``resource_id``s the user is allowed for ``(resource_type, permission)``.

    Used for LIST filters (IDAM-B2 §2.3): the route asks "which storage_profile
    ids may this user list?", and the domain query becomes ``profile_repo.list(ids=allowed)``
    if ``"*"`` not in the result, or ``profile_repo.list()`` otherwise. This is
    the mechanism that makes "``GROUPUSER`` sees ONLY group G's data" provable,
    not vacuous (PS-82 §1/§3.3).

    Returns ``{"*"}`` if the user has admin wildcard OR a role-level grant of
    the permission with no resource constraint (which means "all resources of
    this type in scope").
    """
    g = effective_grants(
        user_id, engine=engine, binding_repo=binding_repo, membership=membership,
    )
    if "*" in g.flat_perms:
        return {"*"}
    # Role-level grant of the same permission → all resources of this type.
    if permission in g.flat_perms:
        return {"*"}
    # Scoped: collect resource_ids that match (rt, perm).
    ids: set[str] = set()
    for (rt, rid, perm) in g.scoped_grants:
        if rt == resource_type and perm == permission:
            ids.add(rid)
    return ids
