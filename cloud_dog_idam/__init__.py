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
from cloud_dog_idam.tokens.jwt import JWTTokenService

__all__ = [
    "APIKeyManager",
    "APIKeyOnlyProvider",
    "JWTTokenService",
    "ProviderRegistry",
    "RBACEngine",
    "migrate_api_keys",
]
__version__ = "0.2.0"
