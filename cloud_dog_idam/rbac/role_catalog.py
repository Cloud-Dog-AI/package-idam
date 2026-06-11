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

# cloud_dog_idam — Role catalogue
"""Canonical role permission strings and baseline role definitions (PS-70/PS-71 IW3A, PS-82 §7, PS-83).

Single source of truth for:
  * the ``idam.roles.read`` / ``idam.roles.write`` permission strings that gate the
    PS-71 §IW3A Roles page (read-only view vs admin write),
  * the PS-82 §7.1 **surface/feature permission catalog** (the canonical permission
    strings every enforcement point — HTTP/MCP/A2A/WebUI — gates on), and
  * the baseline roles that MUST exist and are undeletable. **W28A-741 extended the
    baseline from 2 entries (admin + user) to 6 entries (PS-83 + IDAM-B6 §2.2.A):
    4 principal roles (``admin``/``group-admin``/``user``/``restricted``) plus 2
    cross-cutting grants (``job-control``/``audit-log``). All 6 are undeletable
    per coordinator answer Q4 (PS-71 IW3A.4 generalised) — undeletable ≠
    always-assigned: a service simply doesn't assign ``job-control``/``audit-log``
    if it has no jobs/audit surface, but the catalog entry must not be removable
    (else a service could silently break jobs/audit RBAC).** The ``user`` baseline
    carries the PS-82 §7.2 default grant so a freshly-seeded non-admin can actually
    USE the WebUI/MCP/A2A and its self-service sub-features out of the box
    (the "empty non-admin UI" defect, PS-82 §7 / W28-728-R3).

This is a **platform standard — one definition, all 9+ services inherit it; no
per-service fork** (PS-82 §7.3). Owned by ``cloud_dog_idam`` / ``@cloud-dog/idam``.

Related: docs/standards/82-access-control-session-test-matrix.md §7, PS-70 §3.2
(extended to canonical 6 in same lane per coordinator answer Q5),
docs/standards/71-idam-webui.md §IW3A, docs/standards/idam-canonical-model-map.md,
docs/standards/83-canonical-role-catalog.md §2.1+§2.2 (target catalog this module
materialises).
"""

from __future__ import annotations


# --- Roles-page permission strings (PS-71 §IW3A.5) -------------------------------
IDAM_ROLES_READ = "idam.roles.read"
IDAM_ROLES_WRITE = "idam.roles.write"

#: Wildcard permission held by ``admin`` — grants every permission including roles write.
WILDCARD_PERMISSION = "*"


# --- PS-82 §7.1 surface/feature permission catalog (canonical strings) -----------
# Namespaced like the existing ``idam.*``. EVERY enforcement point (HTTP/MCP/A2A/
# WebUI) gates on these. This is the single canonical catalog — services MUST NOT
# invent their own surface/feature permission strings.

# Surface access (the "can I load this surface at all" gates).
WEBUI_ACCESS = "webui.access"
MCP_ACCESS = "mcp.access"
A2A_ACCESS = "a2a.access"
APIDOCS_ACCESS = "apidocs.access"

# Settings / config.
CONFIG_READ = "config.read"
CONFIG_WRITE = "config.write"
CONFIG_SEED = "config.seed"

# Audit & log.
LOGS_READ = "logs.read"
LOGS_READ_ALL = "logs.read.all"

# Own API keys.
APIKEYS_READ_OWN = "apikeys.read_own"
APIKEYS_MANAGE_OWN = "apikeys.manage_own"

# Service profiles.
PROFILES_READ = "profiles.read"
PROFILES_WRITE = "profiles.write"

# IDAM self-service + admin (own row only; self-filtered at enforcement).
IDAM_USERS_READ = "idam.users.read"
IDAM_USERS_WRITE = "idam.users.write"
IDAM_GROUPS_READ = "idam.groups.read"
IDAM_GROUPS_WRITE = "idam.groups.write"
IDAM_RBAC_READ = "idam.rbac.read"
IDAM_RBAC_WRITE = "idam.rbac.write"
IDAM_AUDIT_READ = "idam.audit.read"            # W28A-741: D-AUDITOR-1 — elevated audit-log grant

# Jobs (PS-75 + PS-76) — W28A-741: D-JOB-CONTROL-1 (canonical strings the central
# ``job-control`` grant carries). ``jobs.archive`` and ``jobs.delete`` are
# admin-only and therefore covered by the wildcard, but registered here so the
# WebUI Roles page can render them.
JOBS_READ = "jobs.read"
JOBS_CONTROL = "jobs.control"
JOBS_ARCHIVE = "jobs.archive"
JOBS_DELETE = "jobs.delete"

#: The canonical §7.1 catalog as a flat, ordered tuple (for registration / discovery
#: by the Roles/RBAC WebUI). ``<domain>.read|write|admin`` strings are service-specific
#: and registered per-lane via the resource registry; only the platform-wide surface/
#: feature strings live here.
SURFACE_FEATURE_PERMISSION_CATALOG: tuple[str, ...] = (
    WEBUI_ACCESS,
    MCP_ACCESS,
    A2A_ACCESS,
    APIDOCS_ACCESS,
    CONFIG_READ,
    CONFIG_WRITE,
    CONFIG_SEED,
    LOGS_READ,
    LOGS_READ_ALL,
    APIKEYS_READ_OWN,
    APIKEYS_MANAGE_OWN,
    PROFILES_READ,
    PROFILES_WRITE,
    IDAM_USERS_READ,
    IDAM_USERS_WRITE,
    IDAM_GROUPS_READ,
    IDAM_GROUPS_WRITE,
    IDAM_RBAC_READ,
    IDAM_RBAC_WRITE,
    IDAM_AUDIT_READ,
    IDAM_ROLES_READ,
    IDAM_ROLES_WRITE,
    JOBS_READ,
    JOBS_CONTROL,
    JOBS_ARCHIVE,
    JOBS_DELETE,
)


# --- Baseline roles (PS-71 §IW3A.4 generalised; all 6 undeletable per W28A-741) --
#: PS-82 §7.2 default ``user`` baseline grant — seeded by default so a non-admin
#: works out of the box (IW1.6-class hard guard). GRANTED here; NOT-granted
#: admin/elevated permissions (``config.write``/``config.seed``,
#: ``logs.read.all``, ``profiles.write``, ``idam.roles.*``/``idam.rbac.*``/
#: ``idam.groups.write``, other-user writes, secret reveal, ``<domain>.write``/
#: ``<domain>.admin``) are deliberately absent → they resolve to 403-inline at the
#: enforcement point, never a blank UI.
#:
#: ``resources:read`` is retained for backward compatibility with the pre-PS-82
#: RBACEngine default (UT1.7 / UT1.39 / ST1.12). ``<domain>.read`` is granted per-lane
#: (in-scope / group-scoped) by each service via the resource registry, not here.
USER_BASELINE_PERMISSIONS: set[str] = {
    # backward-compat default
    "resources:read",
    # §7.1 surfaces
    WEBUI_ACCESS,
    MCP_ACCESS,
    A2A_ACCESS,
    APIDOCS_ACCESS,
    # self-service IDAM (own row only — self-filtered at enforcement)
    IDAM_USERS_READ,
    # own API keys
    APIKEYS_READ_OWN,
    APIKEYS_MANAGE_OWN,
    # read-only config (secrets masked) + own/service logs + profiles read
    CONFIG_READ,
    LOGS_READ,
    PROFILES_READ,
}

#: W28A-741: D-CENTRAL-1 + D-GROUP-ADMIN-1 — the ``group-admin`` baseline.
#: Group-admin manages MEMBERSHIP of group(s) it administers + the group's
#: resource bindings (IDAM-B6 §2.2.A row 2 + IDAM-B2 §2.4). It inherits the
#: ``user`` baseline (so a group-admin can also use the WebUI/MCP/A2A for normal
#: self-service) PLUS the group/RBAC management strings. Scope-to-owned-groups
#: is enforced at the guard via ``resource_type`` checks — the baseline grant
#: gives the surface gates, the per-binding rows give the per-resource scope.
GROUP_ADMIN_BASELINE_PERMISSIONS: set[str] = set(USER_BASELINE_PERMISSIONS) | {
    IDAM_USERS_READ,       # read all users in admin/group scope (for member picker)
    IDAM_GROUPS_READ,
    IDAM_GROUPS_WRITE,     # scoped to owned groups via guard's resource_id check
    IDAM_RBAC_READ,
    IDAM_RBAC_WRITE,       # scoped via guard
}

#: W28A-741: D-CENTRAL-1 — the ``restricted`` baseline. Quarantined principal:
#: below ``user``; explicit grants only (IDAM-B6 §2.2.A row 4). NO baseline
#: surface access — every gated request → 403 inline until an explicit
#: ``RBACBinding`` grants the specific ``(resource_type, resource_id, permission)``.
#: Authentication still succeeds (so the login → 401 distinction holds); it's
#: the AUTHORISATION that defaults to deny.
RESTRICTED_BASELINE_PERMISSIONS: set[str] = set()

#: W28A-741: D-JOB-CONTROL-1 — the cross-cutting ``job-control`` grant
#: (additive, NOT a stand-alone principal). Holder gets `jobs.read` + `jobs.control`
#: (cancel/retry/reschedule); admin-only `jobs.archive`/`jobs.delete` remain admin
#: via the wildcard `*` and are NOT included in this grant. Surface/feature gate:
#: ``mcp.access`` is still required to call the job tools, so this grant is
#: typically combined with a principal role that has surface access (e.g. ``user``).
JOB_CONTROL_GRANT_PERMISSIONS: set[str] = {
    JOBS_READ,
    JOBS_CONTROL,
}

#: W28A-741: D-AUDITOR-1 — the cross-cutting ``audit-log`` grant (additive).
#: Holder gets ``logs.read.all`` + ``idam.audit.read`` ELEVATED. Base ``logs.read``
#: (own+service scope) is already in the ``user`` baseline and so is held by any
#: ``user`` principal that ALSO holds this grant. ``admin`` holds both via ``*``.
#: This is the central definition — sql-agent/db-mcp ``auditor`` business roles
#: compose with this grant rather than reinventing it (per PS-83 §5 D-AUDITOR-1
#: disposition).
AUDIT_LOG_GRANT_PERMISSIONS: set[str] = {
    LOGS_READ_ALL,
    IDAM_AUDIT_READ,
}

#: Names of the platform baseline roles + cross-cutting grants. **All 6 undeletable**
#: per W28A-741 coordinator answer Q4: undeletable ≠ always-assigned. A service
#: simply doesn't assign ``job-control``/``audit-log`` if it has no jobs/audit
#: surface — but the catalog entry MUST NOT be deletable (else a service could
#: remove ``job-control`` and silently break jobs RBAC). PS-71 IW3A.4
#: generalised to the canonical 6.
BASELINE_ROLE_NAMES: frozenset[str] = frozenset({
    # 4 principal roles
    "admin", "group-admin", "user", "restricted",
    # 2 cross-cutting grants (additive, held alongside a principal)
    "job-control", "audit-log",
})

#: Subset: the 4 principal roles (held by a user as their primary identity).
PRINCIPAL_ROLE_NAMES: frozenset[str] = frozenset({
    "admin", "group-admin", "user", "restricted",
})

#: Subset: the 2 cross-cutting grants (additive permission bundles).
CROSS_CUTTING_GRANT_NAMES: frozenset[str] = frozenset({
    "job-control", "audit-log",
})

#: Baseline role/grant -> permission set. Mirrors the canonical PS-83 §2 catalog.
#: ``RBACEngine.__init__`` ALWAYS starts from this dict and merges per-service
#: ``role_overlay=`` on top (per-role union; never erases a baseline permission
#: — D-NO-BASELINE-1 fix).
BASELINE_ROLE_PERMISSIONS: dict[str, set[str]] = {
    # principals
    "admin": {WILDCARD_PERMISSION},
    "group-admin": set(GROUP_ADMIN_BASELINE_PERMISSIONS),
    "user": set(USER_BASELINE_PERMISSIONS),
    "restricted": set(RESTRICTED_BASELINE_PERMISSIONS),
    # cross-cutting grants — held alongside a principal role; additive
    "job-control": set(JOB_CONTROL_GRANT_PERMISSIONS),
    "audit-log": set(AUDIT_LOG_GRANT_PERMISSIONS),
}


def can_read_roles(permissions: set[str]) -> bool:
    """Return whether a permission set may VIEW the Roles page (IW3A.5)."""
    return WILDCARD_PERMISSION in permissions or IDAM_ROLES_READ in permissions


def can_write_roles(permissions: set[str]) -> bool:
    """Return whether a permission set may CREATE/EDIT/DELETE roles (IW3A.5)."""
    return WILDCARD_PERMISSION in permissions or IDAM_ROLES_WRITE in permissions


def is_undeletable_role(name: str) -> bool:
    """Return whether a role name is one of the 6 undeletable canonical entries.

    Per W28A-741 coordinator answer Q4: PS-71 IW3A.4 generalised — all 4 principal
    roles AND both cross-cutting grants are undeletable. PS-71 IW3A "Roles page"
    delete action MUST be blocked for any of these 6 names.
    """
    return name in BASELINE_ROLE_NAMES
