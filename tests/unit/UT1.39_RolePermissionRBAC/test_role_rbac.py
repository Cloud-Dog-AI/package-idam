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

# W28A-876 Gate 1 — PS-71 §IW3A.5 Roles-page RBAC contract.
# Proves the read/write gating semantics for the Roles page: admin (wildcard) and an
# explicit idam.roles.write holder may write; a read-only (idam.roles.read) principal
# may view but NOT write; a principal with neither is denied both. Verified both via
# the role_catalog helpers and the canonical PermissionChecker.

from __future__ import annotations

from cloud_dog_idam.rbac.permissions import PermissionChecker
from cloud_dog_idam.rbac.role_catalog import (
    BASELINE_ROLE_NAMES,
    BASELINE_ROLE_PERMISSIONS,
    IDAM_ROLES_READ,
    IDAM_ROLES_WRITE,
    can_read_roles,
    can_write_roles,
)


def _checker(perms: set[str]) -> PermissionChecker:
    return PermissionChecker(permissions=perms, user_id="u", owned_groups=set())


def test_admin_wildcard_can_read_and_write() -> None:
    perms = {"*"}
    assert can_read_roles(perms) and can_write_roles(perms)
    assert _checker(perms).has_permission(IDAM_ROLES_WRITE)


def test_explicit_write_holder_can_write() -> None:
    perms = {IDAM_ROLES_WRITE}
    assert can_write_roles(perms)
    assert _checker(perms).has_permission(IDAM_ROLES_WRITE)


def test_read_only_principal_can_view_but_not_write() -> None:
    perms = {IDAM_ROLES_READ}
    assert can_read_roles(perms) is True
    assert can_write_roles(perms) is False
    assert _checker(perms).has_permission(IDAM_ROLES_READ) is True
    assert _checker(perms).has_permission(IDAM_ROLES_WRITE) is False


def test_principal_without_idam_visibility_is_denied_both() -> None:
    perms = {"resources:read"}
    assert can_read_roles(perms) is False
    assert can_write_roles(perms) is False


def test_baseline_catalog_matches_engine_defaults() -> None:
    # Baseline names and permission sets are the single source of truth.
    # W28A-741 extended the catalog from 2 to 6 entries per PS-83 + IDAM-B6
    # §2.2.A (4 principal roles + 2 cross-cutting grants); PS-71 IW3A.4
    # generalised: all 6 undeletable (coordinator answer Q4).
    assert BASELINE_ROLE_NAMES == frozenset({
        # 4 principal roles
        "admin", "group-admin", "user", "restricted",
        # 2 cross-cutting grants (additive permission bundles)
        "job-control", "audit-log",
    })
    assert BASELINE_ROLE_PERMISSIONS["admin"] == {"*"}
    assert "resources:read" in BASELINE_ROLE_PERMISSIONS["user"]
    # group-admin inherits the user baseline + adds group/RBAC management
    assert "webui.access" in BASELINE_ROLE_PERMISSIONS["group-admin"]
    assert "idam.groups.write" in BASELINE_ROLE_PERMISSIONS["group-admin"]
    # restricted has empty baseline (default-DENY until explicitly bound)
    assert BASELINE_ROLE_PERMISSIONS["restricted"] == set()
    # job-control grant: jobs.read + jobs.control (admin-only archive/delete via *)
    assert BASELINE_ROLE_PERMISSIONS["job-control"] == {"jobs.read", "jobs.control"}
    # audit-log grant: elevated logs.read.all + idam.audit.read
    assert BASELINE_ROLE_PERMISSIONS["audit-log"] == {"logs.read.all", "idam.audit.read"}
