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

# cloud_dog_idam — PS-70 Identity & Access Management for Cloud-Dog services
"""Public API for cloud_dog_idam."""

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.migration.api_keys import migrate_api_keys
from cloud_dog_idam.providers.api_key_only import APIKeyOnlyProvider
from cloud_dog_idam.providers.registry import ProviderRegistry
from cloud_dog_idam.rbac.engine import RBACEngine
from cloud_dog_idam.rbac.grants import (
    ResolvedGrants,
    allowed_resource_ids,
    authorise,
    effective_grants,
)
from cloud_dog_idam.rbac.guard_registry import (
    PUBLIC_ALLOWLIST,
    is_route_guarded,
    register_guard,
)
from cloud_dog_idam.rbac.membership import (
    MembershipResolver,
    SqlAlchemyMembershipResolver,
    StaticMembershipResolver,
)
from cloud_dog_idam.rbac.resource_registry import ResourceRegistryService
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
)
from cloud_dog_idam.rbac.secret_masking import mask_secrets
from cloud_dog_idam.security.totp import TOTPManager
from cloud_dog_idam.tokens.jwt import JWTTokenService
from cloud_dog_idam.users.cascade import CascadeDeleteResult, delete_user_cascade

__all__ = [
    "APIKeyManager",
    "APIKeyOnlyProvider",
    # Baseline role catalog (W28A-741: D-CENTRAL-1 — 4 principal + 2 grants)
    "BASELINE_ROLE_NAMES",
    "BASELINE_ROLE_PERMISSIONS",
    "PRINCIPAL_ROLE_NAMES",
    "CROSS_CUTTING_GRANT_NAMES",
    "USER_BASELINE_PERMISSIONS",
    "GROUP_ADMIN_BASELINE_PERMISSIONS",
    "RESTRICTED_BASELINE_PERMISSIONS",
    "JOB_CONTROL_GRANT_PERMISSIONS",
    "AUDIT_LOG_GRANT_PERMISSIONS",
    "SURFACE_FEATURE_PERMISSION_CATALOG",
    # Standard exports
    "CascadeDeleteResult",
    "JWTTokenService",
    "ProviderRegistry",
    "RBACEngine",
    "ResourceRegistryService",
    "TOTPManager",
    "delete_user_cascade",
    "migrate_api_keys",
    # W28A-741: NEW resource-aware resolver (D-NO-BINDING-1)
    "ResolvedGrants",
    "effective_grants",
    "authorise",
    "allowed_resource_ids",
    "MembershipResolver",
    "SqlAlchemyMembershipResolver",
    "StaticMembershipResolver",
    # W28A-741: Guard registry + secret masking (IDAM-B2 §3.2 + §3.3)
    "PUBLIC_ALLOWLIST",
    "register_guard",
    "is_route_guarded",
    "mask_secrets",
]
#: Package version. W28A-741 reconciles the prior 0.3.2 / 0.4.0 drift (the
#: pyproject.toml had 0.4.0 while ``__version__`` here was 0.3.2). Minor-bump
#: from 0.3.2 → 0.5.0 justified because the surface is ADDITIVE (resolver,
#: resource-aware guard, binding routes, central baseline roles, secret
#: masking, flat-roles central) — no breaking change, the legacy
#: ``RBACEngine(role_permissions=...)`` and ``require_permission(permission, rbac)``
#: forms are preserved as DeprecationWarning shims per coord answer Q3.
__version__ = "0.5.0"
