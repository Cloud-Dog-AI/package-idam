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

# cloud_dog_idam — Central flat-roles source of truth (W28A-741: D-DUAL-VOCAB-1)
"""Central Thread-a flat-roles surface — single source of truth.

PS-83 §3.10 + W28A-740 §5 D-DUAL-VOCAB-1: 4 services (chat-client, file-mcp,
git-mcp, notification-agent) ship a per-service ``web_flat_roles.py`` with the
same 3-flat-role surface (``admin`` / ``read-write`` / ``read-only``) plus
legacy aliases. The per-service files have DRIFTED:

  - chat-client `web_flat_roles.py:91-138` has aliases incl. `{"writer",
    "editor", "user", "member"}` → `read-write`; everything else falls through
    to `read-only`.
  - git-mcp `web_flat_roles.py:91-100` has `FLAT_TO_TOOL_ROLE` mapping flat
    roles onto the tool-RBAC vocabulary (`maintainer`/`writer`/`reader`).
  - file-mcp + notification-agent have the flat roles but NOT the tool-RBAC
    bridge (incomplete).

This module is the central source-of-truth the 4 services collapse onto
(W28A-742…751 follow-up — per-service ``web_flat_roles.py`` becomes a 1-line
re-export from here).

**This lane (W28A-741) ships the central module only.** Per-service service
code is NOT touched in keystone scope; the per-service rename to consume this
central module is W28A-742…751 follow-up.
"""

from __future__ import annotations


# --- The three flat roles ---------------------------------------------------------
ADMIN_ROLE = "admin"
READ_WRITE_ROLE = "read-write"
READ_ONLY_ROLE = "read-only"

#: The three flat roles in descending privilege order.
FLAT_ROLES: tuple[str, ...] = (ADMIN_ROLE, READ_WRITE_ROLE, READ_ONLY_ROLE)


# --- Legacy aliases (from the per-service files) ----------------------------------
#: Canonical legacy alias map — the union of what the 4 per-service files do today
#: (chat-client `web_flat_roles.py:134-138` set is the most permissive). Mapping
#: legacy names to the canonical 3 flat roles. Per-service overrides allowed by
#: passing ``aliases=`` to ``normalise_flat_role``.
#:
#: Notes on individual mappings:
#: - ``owner``/``superuser``/``super-admin`` → ``admin``: legacy admin synonyms
#: - ``writer``/``editor``/``user``/``member`` → ``read-write``: legacy non-admin
#:   producers (the "user" alias preserves a default-to-readwrite behaviour for
#:   pre-PS-83 services)
#: - ``viewer``/``reader`` → ``read-only``: legacy consumers (D-VIEWER-1 — the
#:   ``viewer`` legacy term is preserved here as an alias but the central
#:   surface uses ``read-only`` per the W28A-740 disagreement)
DEFAULT_LEGACY_ALIASES: dict[str, str] = {
    "owner": ADMIN_ROLE,
    "superuser": ADMIN_ROLE,
    "super-admin": ADMIN_ROLE,
    "readwrite": READ_WRITE_ROLE,
    "writer": READ_WRITE_ROLE,
    "editor": READ_WRITE_ROLE,
    "user": READ_WRITE_ROLE,
    "member": READ_WRITE_ROLE,
    "viewer": READ_ONLY_ROLE,
    "reader": READ_ONLY_ROLE,
}


def normalise_flat_role(
    raw: str | None,
    *,
    aliases: dict[str, str] | None = None,
) -> str:
    """Normalise an arbitrary role-name string to one of the 3 flat roles.

    Semantics:
      - Empty/None/unrecognised → ``read-only`` (default-DENIest floor; PS-82
        §3.1 default-DENY for non-admin surfaces).
      - Whitespace stripped; case-insensitive.
      - Canonical 3 names (``admin``/``read-write``/``read-only``) pass through.
      - Legacy names alias-mapped via ``DEFAULT_LEGACY_ALIASES`` (override with
        the ``aliases=`` kwarg for per-service customisation).
    """
    key = (raw or "").strip().lower()
    if not key:
        return READ_ONLY_ROLE
    if key in {ADMIN_ROLE, READ_WRITE_ROLE, READ_ONLY_ROLE}:
        return key
    alias_map = aliases if aliases is not None else DEFAULT_LEGACY_ALIASES
    return alias_map.get(key, READ_ONLY_ROLE)


def is_admin(role: str | None) -> bool:
    """Return True iff the normalised role is ``admin``."""
    return normalise_flat_role(role) == ADMIN_ROLE


def is_writeable(role: str | None) -> bool:
    """Return True iff the normalised role is ``admin`` or ``read-write``."""
    return normalise_flat_role(role) in {ADMIN_ROLE, READ_WRITE_ROLE}


# --- Generic FLAT_TO_TOOL_ROLE factory --------------------------------------------
def make_flat_to_tool_role(
    *,
    admin_role: str = "admin",
    writer_roles: tuple[str, ...] = ("writer",),
    reader_role: str = "reader",
) -> dict[str, tuple[str, ...]]:
    """Build the per-service ``FLAT_TO_TOOL_ROLE`` mapping.

    Each per-service web layer translates its flat session role onto the
    per-tool RBAC vocabulary it enforces at API time. The shape is identical
    across services; the role NAMES differ.

    Example (git-mcp): ``make_flat_to_tool_role(writer_roles=("writer",),
    reader_role="reader")`` → ``{admin: (admin,), read-write: (writer, reader),
    read-only: (reader,)}``.

    Per IDAM-B2: ``read-write → (writer, reader)`` preserves read-write ≥
    read-only invariant by ensuring write-roles carry the read perm set too.
    """
    return {
        ADMIN_ROLE: (admin_role,),
        READ_WRITE_ROLE: writer_roles + (reader_role,),
        READ_ONLY_ROLE: (reader_role,),
    }
