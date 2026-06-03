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

# cloud_dog_idam — Local password provider
"""Local username/password authentication using Argon2id."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, User
from cloud_dog_idam.domain.enums import UserStatus
from cloud_dog_idam.providers.base import AuthProvider


class LocalPasswordProvider(AuthProvider):
    """Represent local password provider."""
    def __init__(self, user_lookup, *, password_field: str = "password_hash") -> None:
        self._lookup = user_lookup
        self._password_field = password_field
        self._hasher = PasswordHasher()

    def hash_password(self, raw_password: str) -> str:
        """Handle hash password."""
        return self._hasher.hash(raw_password)

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == "local_password"

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        user = self._lookup(request.principal)
        if user is None:
            raise AuthenticationError("Unknown user")
        if user.status in {UserStatus.DISABLED, UserStatus.LOCKED}:
            raise AuthenticationError("User disabled or locked")
        password_hash = getattr(user, self._password_field, "")
        try:
            self._hasher.verify(password_hash, request.secret)
        except VerifyMismatchError as exc:
            raise AuthenticationError("Invalid credentials") from exc
        return AuthResult(user=user)


class LocalUser(User):
    """Represent local user."""
    password_hash: str = ""
