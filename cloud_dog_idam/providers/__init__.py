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

# cloud_dog_idam — provider exports
"""Provider and browser-flow exports for application embedding."""

from .api_key import APIKeyProvider
from .api_key_only import APIKeyOnlyProvider
from .base import AuthProvider
from .browser_automation import (
    BrowserAutomationError,
    BrowserCredentials,
    BrowserFlowResult,
    InteractiveAuthStart,
    OIDCBrowserAutomation,
)
from .ldap import LDAPProvider
from .local_password import LocalPasswordProvider
from .oidc import (
    Auth0Provider,
    BasicOIDCProvider,
    GoogleProvider,
    KeycloakProvider,
    OIDCAuthContext,
    OIDCAuthorizationSession,
)
from .os_pam import OSPAMProvider
from .registry import ProviderRegistry
from .saml import SAMLConfig, SAMLProvider

__all__ = [
    "APIKeyProvider",
    "APIKeyOnlyProvider",
    "Auth0Provider",
    "AuthProvider",
    "BasicOIDCProvider",
    "BrowserAutomationError",
    "BrowserCredentials",
    "BrowserFlowResult",
    "GoogleProvider",
    "InteractiveAuthStart",
    "KeycloakProvider",
    "LDAPProvider",
    "LocalPasswordProvider",
    "OIDCAuthContext",
    "OIDCAuthorizationSession",
    "OIDCBrowserAutomation",
    "OSPAMProvider",
    "ProviderRegistry",
    "SAMLConfig",
    "SAMLProvider",
]
