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

# cloud_dog_idam — LDAP provider
"""LDAP bind authentication and group resolution with python-ldap/ldap3 support."""

from __future__ import annotations

from dataclasses import dataclass
import warnings

from cloud_dog_idam.domain.errors import AuthenticationError
from cloud_dog_idam.domain.models import AuthRequest, AuthResult, User
from cloud_dog_idam.providers.base import AuthProvider

try:  # pragma: no cover - optional dependency
    import ldap  # type: ignore
except ImportError:  # pragma: no cover
    ldap = None

try:  # pragma: no cover - optional dependency
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            module="pyasn1.codec.ber.encoder",
        )
        from ldap3 import ALL, Connection, Server  # type: ignore
except ImportError:  # pragma: no cover
    Connection = None
    Server = None
    ALL = None


@dataclass(slots=True)
class LDAPConfig:
    """Represent l d a p config."""
    host: str
    port: int = 389
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    user_search_base: str = ""
    user_search_filter: str = "(uid={username})"
    group_search_base: str = ""
    group_search_filter: str = "(member={user_dn})"
    timeout_seconds: int = 10
    use_ssl: bool = False
    use_starttls: bool = False


class LDAPProvider(AuthProvider):
    """Represent l d a p provider."""
    def __init__(
        self, bind_fn=None, group_fn=None, config: LDAPConfig | None = None
    ) -> None:
        self._bind_fn = bind_fn
        self._group_fn = group_fn
        self._config = config

    async def supports(self, auth_type: str) -> bool:
        """Handle supports."""
        return auth_type == "ldap"

    def _search_and_bind_python_ldap(
        self, username: str, password: str
    ) -> tuple[str, list[str]]:
        if ldap is None or self._config is None:
            raise AuthenticationError("python-ldap not configured")
        proto = "ldaps" if self._config.use_ssl else "ldap"
        uri = f"{proto}://{self._config.host}:{self._config.port}"
        conn = ldap.initialize(uri)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self._config.timeout_seconds)
        if self._config.use_starttls:
            conn.start_tls_s()
        conn.simple_bind_s(self._config.bind_dn, self._config.bind_password)

        if "," in username and "=" in username:
            user_dn = username
        else:
            user_base = self._config.user_search_base or self._config.base_dn
            user_filter = self._config.user_search_filter.format(username=username)
            users = conn.search_s(user_base, ldap.SCOPE_SUBTREE, user_filter)
            if not users:
                raise AuthenticationError("LDAP user not found")
            user_dn = users[0][0]
        conn.simple_bind_s(user_dn, password)

        groups: list[str] = []
        group_base = self._config.group_search_base or self._config.base_dn
        group_filter = self._config.group_search_filter.format(user_dn=user_dn)
        for dn, attrs in conn.search_s(group_base, ldap.SCOPE_SUBTREE, group_filter):
            if dn and attrs:
                cn = attrs.get("cn") or []
                if cn:
                    val = cn[0]
                    groups.append(
                        val.decode("utf-8") if isinstance(val, bytes) else str(val)
                    )
        return user_dn, groups

    def _search_and_bind_ldap3(
        self, username: str, password: str
    ) -> tuple[str, list[str]]:
        if Connection is None or Server is None or self._config is None:
            raise AuthenticationError("ldap3 not configured")
        server = Server(
            self._config.host,
            port=self._config.port,
            use_ssl=self._config.use_ssl,
            get_info=ALL,
        )
        admin = Connection(
            server,
            user=self._config.bind_dn,
            password=self._config.bind_password,
            receive_timeout=self._config.timeout_seconds,
            auto_bind=True,
        )
        try:
            if "," in username and "=" in username:
                user_dn = username
            else:
                user_base = self._config.user_search_base or self._config.base_dn
                user_filter = self._config.user_search_filter.format(username=username)
                admin.search(user_base, user_filter, attributes=["*"])
                if not admin.entries:
                    raise AuthenticationError("LDAP user not found")
                user_dn = admin.entries[0].entry_dn

            user_conn = Connection(
                server,
                user=user_dn,
                password=password,
                receive_timeout=self._config.timeout_seconds,
                auto_bind=True,
            )
            try:
                pass
            finally:
                user_conn.unbind()

            groups: list[str] = []
            group_base = self._config.group_search_base or self._config.base_dn
            group_filter = self._config.group_search_filter.format(user_dn=user_dn)
            admin.search(group_base, group_filter, attributes=["cn"])
            for entry in admin.entries:
                cn = entry.entry_attributes_as_dict.get("cn", [])
                if cn:
                    groups.append(str(cn[0]))
            return user_dn, groups
        finally:
            admin.unbind()

    async def authenticate(self, request: AuthRequest) -> AuthResult:
        """Handle authenticate."""
        if self._bind_fn is not None:
            outcome = self._bind_fn(request.principal, request.secret)
            if not outcome:
                raise AuthenticationError("LDAP bind failed")
            groups = self._group_fn(request.principal) if self._group_fn else []
            user = User(
                username=request.principal,
                email=f"{request.principal}@ldap",
                display_name=request.principal,
            )
            return AuthResult(user=user, claims={"groups": groups})

        if self._config is None:
            raise AuthenticationError("LDAP config missing")

        try:
            user_dn, groups = self._search_and_bind_python_ldap(
                request.principal, request.secret
            )
        except Exception:
            user_dn, groups = self._search_and_bind_ldap3(
                request.principal, request.secret
            )

        user = User(
            username=request.principal,
            email=f"{request.principal}@ldap",
            display_name=request.principal,
        )
        return AuthResult(user=user, claims={"groups": groups, "dn": user_dn})
