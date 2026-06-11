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

# cloud_dog_idam — Domain enums
"""Domain enums for status and provider handling."""

from __future__ import annotations

from enum import Enum


class UserStatus(str, Enum):
    """Represent user status."""
    INITIALISING = "initialising"
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"
    PENDING_APPROVAL = "pending_approval"


class ProviderType(str, Enum):
    """Represent provider type."""
    LOCAL_PASSWORD = "local_password"
    API_KEY = "api_key"
    OIDC = "oidc"
    LDAP = "ldap"
    OS_PAM = "os_pam"
    SAML = "saml"


class ProvisioningMode(str, Enum):
    """Represent provisioning mode."""
    MANUAL = "manual"
    JIT = "jit"
    SYNC = "sync"
