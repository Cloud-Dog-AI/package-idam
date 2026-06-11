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

# cloud_dog_idam — RBAC exports
"""RBAC engine, permission checker, and policy extension hooks."""

from cloud_dog_idam.rbac.engine import RBACEngine
from cloud_dog_idam.rbac.flat_roles import (
    ADMIN_ROLE,
    DEFAULT_LEGACY_ALIASES,
    FLAT_ROLES,
    READ_ONLY_ROLE,
    READ_WRITE_ROLE,
    is_admin,
    is_writeable,
    make_flat_to_tool_role,
    normalise_flat_role,
)
from cloud_dog_idam.rbac.grants import (
    GRANT_TUPLE_DELIM,
    ResolvedGrants,
    allowed_resource_ids,
    authorise,
    decode_grant_tuple,
    effective_grants,
    encode_grant_tuple,
)
from cloud_dog_idam.rbac.guard_registry import (
    PUBLIC_ALLOWLIST,
    GuardMetadata,
    get_guard,
    is_route_guarded,
    register_guard,
    registered_routes,
    reset_registry,
)
from cloud_dog_idam.rbac.membership import (
    MembershipResolver,
    SqlAlchemyMembershipResolver,
    StaticMembershipResolver,
)
from cloud_dog_idam.rbac.permissions import PermissionChecker
from cloud_dog_idam.rbac.policy_extensions import (
    authorise_with_extensions,
    clear_policy_evaluators,
    deregister_policy_evaluator,
    evaluate_policy_extensions,
    list_policy_evaluators,
    register_policy_evaluator,
)
from cloud_dog_idam.rbac.resource_registry import (
    PLATFORM_RESOURCE_TYPES,
    ResourceRegistryService,
)
from cloud_dog_idam.rbac.role_catalog import (
    AUDIT_LOG_GRANT_PERMISSIONS,
    BASELINE_ROLE_NAMES,
    BASELINE_ROLE_PERMISSIONS,
    CROSS_CUTTING_GRANT_NAMES,
    GROUP_ADMIN_BASELINE_PERMISSIONS,
    JOB_CONTROL_GRANT_PERMISSIONS,
    PRINCIPAL_ROLE_NAMES,
    RESTRICTED_BASELINE_PERMISSIONS,
    SURFACE_FEATURE_PERMISSION_CATALOG,
    USER_BASELINE_PERMISSIONS,
    can_read_roles,
    can_write_roles,
    is_undeletable_role,
)
from cloud_dog_idam.rbac.secret_masking import (
    REDACTED_PLACEHOLDER,
    SECRET_KEY_TOKENS,
    SECRET_SUFFIX_TOKENS,
    is_secret_key,
    mask_secrets,
)

__all__ = [
    # Engine + classic types
    "RBACEngine",
    "PermissionChecker",
    "PLATFORM_RESOURCE_TYPES",
    "ResourceRegistryService",
    # Policy extension hooks
    "authorise_with_extensions",
    "clear_policy_evaluators",
    "deregister_policy_evaluator",
    "evaluate_policy_extensions",
    "list_policy_evaluators",
    "register_policy_evaluator",
    # W28A-741: NEW resolver (D-NO-BINDING-1 fix — IDAM-B2 §2.2)
    "ResolvedGrants",
    "effective_grants",
    "authorise",
    "allowed_resource_ids",
    "GRANT_TUPLE_DELIM",
    "encode_grant_tuple",
    "decode_grant_tuple",
    # W28A-741: Membership port
    "MembershipResolver",
    "SqlAlchemyMembershipResolver",
    "StaticMembershipResolver",
    # W28A-741: Guard metadata registry (IDAM-B2 §3.2)
    "GuardMetadata",
    "PUBLIC_ALLOWLIST",
    "register_guard",
    "get_guard",
    "is_route_guarded",
    "registered_routes",
    "reset_registry",
    # W28A-741: Central secret-masking (IDAM-B2 §3.3)
    "mask_secrets",
    "is_secret_key",
    "SECRET_KEY_TOKENS",
    "SECRET_SUFFIX_TOKENS",
    "REDACTED_PLACEHOLDER",
    # W28A-741: Central flat-roles (D-DUAL-VOCAB-1)
    "ADMIN_ROLE",
    "READ_WRITE_ROLE",
    "READ_ONLY_ROLE",
    "FLAT_ROLES",
    "DEFAULT_LEGACY_ALIASES",
    "normalise_flat_role",
    "is_admin",
    "is_writeable",
    "make_flat_to_tool_role",
    # W28A-741: Role catalog (D-CENTRAL-1 + D-AUDITOR-1 + D-JOB-CONTROL-1)
    "BASELINE_ROLE_NAMES",
    "PRINCIPAL_ROLE_NAMES",
    "CROSS_CUTTING_GRANT_NAMES",
    "BASELINE_ROLE_PERMISSIONS",
    "USER_BASELINE_PERMISSIONS",
    "GROUP_ADMIN_BASELINE_PERMISSIONS",
    "RESTRICTED_BASELINE_PERMISSIONS",
    "JOB_CONTROL_GRANT_PERMISSIONS",
    "AUDIT_LOG_GRANT_PERMISSIONS",
    "SURFACE_FEATURE_PERMISSION_CATALOG",
    "can_read_roles",
    "can_write_roles",
    "is_undeletable_role",
]
