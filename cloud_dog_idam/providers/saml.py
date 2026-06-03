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

# cloud_dog_idam — SAML provider
"""SAML 2.0 SP authentication provider using python3-saml when available."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, User
from cloud_dog_idam.providers.base import AuthProvider

try:  # pragma: no cover - optional dependency
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore
except ImportError:  # pragma: no cover
    OneLogin_Saml2_Auth = None


@dataclass(slots=True)
class SAMLConfig:
    """Represent s a m l config."""
    settings: dict[str, Any]


class SAMLProvider(AuthProvider):
    """Represent s a m l provider."""
    def __init__(self, config: SAMLConfig | None = None) -> None:
        self._config = config

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == "saml"

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        if OneLogin_Saml2_Auth is None:
            raise AuthenticationError("python3-saml is not installed")
        if self._config is None:
            raise AuthenticationError("SAML configuration missing")

        req_data = request.metadata.get("http_request")
        if not isinstance(req_data, dict):
            raise AuthenticationError("SAML request metadata missing http_request")

        auth = OneLogin_Saml2_Auth(req_data, old_settings=self._config.settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise AuthenticationError(f"SAML response errors: {', '.join(errors)}")
        if not auth.is_authenticated():
            raise AuthenticationError("SAML response not authenticated")

        name_id = auth.get_nameid() or ""
        attrs = auth.get_attributes() or {}
        email_values = attrs.get("email") or attrs.get("mail") or []
        email = email_values[0] if email_values else ""
        user = User(
            username=name_id or email,
            email=email,
            display_name=(attrs.get("displayName") or [name_id])[0],
        )
        return AuthResult(user=user, claims={"saml_attributes": attrs})
