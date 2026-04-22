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

# cloud_dog_idam — token exports
"""Token services and session extension helpers."""

from cloud_dog_idam.tokens.jwt import JWTTokenService
from cloud_dog_idam.tokens.opaque import OpaqueTokenService
from cloud_dog_idam.tokens.refresh import RefreshTokenStore
from cloud_dog_idam.tokens.session_extensions import (
    apply_session_extensions,
    clear_session_extensions,
    list_session_extensions,
    load_session_extensions,
    register_session_extension,
)
from cloud_dog_idam.tokens.sessions import Session, SessionManager

__all__ = [
    "JWTTokenService",
    "OpaqueTokenService",
    "RefreshTokenStore",
    "Session",
    "SessionManager",
    "apply_session_extensions",
    "clear_session_extensions",
    "list_session_extensions",
    "load_session_extensions",
    "register_session_extension",
]
