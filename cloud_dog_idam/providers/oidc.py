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

# cloud_dog_idam — OIDC provider adapters
"""OIDC provider abstractions for Keycloak/Auth0/Google with discovery/JWKS validation."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import jwt
from jwt import PyJWKClientError


@dataclass(slots=True)
class TokenSet:
    """Represent token set."""
    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int = 3600


@dataclass(slots=True)
class UserInfo:
    """Represent user info."""
    sub: str
    email: str | None = None
    name: str | None = None
    claims: dict[str, Any] | None = None


@dataclass(slots=True)
class _DiscoveryCache:
    document: dict[str, Any]
    expires_at: float


@dataclass(slots=True)
class OIDCAuthContext:
    """Represent o i d c auth context."""
    state: str
    nonce: str
    code_verifier: str
    code_challenge: str


@dataclass(slots=True)
class OIDCAuthorizationSession:
    """Represent o i d c authorization session."""
    authorization_url: str
    context: OIDCAuthContext


class OIDCProvider(Protocol):
    """Define the OIDC provider interface used by IDAM integrations."""

    def get_authorization_url(self, state: str, nonce: str, **kwargs) -> str:
        """Build the user authorization URL."""
        ...

    async def exchange_code(self, code: str, redirect_uri: str) -> TokenSet:
        """Exchange an authorization code for tokens."""
        ...

    async def get_userinfo(self, access_token: str) -> UserInfo:
        """Return user information for the access token."""
        ...

    async def refresh_token(self, refresh_token: str) -> TokenSet:
        """Refresh tokens using the refresh token."""
        ...

    def map_claims_to_user(self, claims: dict) -> dict:
        """Map OIDC claims into the platform user model."""
        ...

    def map_claims_to_roles(self, claims: dict) -> list[str]:
        """Map OIDC claims into platform role names."""
        ...

    async def validate_id_token(self, id_token: str) -> dict:
        """Validate an ID token and return its claims."""
        ...

    def get_logout_url(self, **kwargs) -> str | None:
        """Return a logout URL when the provider supports one."""
        ...


class BasicOIDCProvider:
    """Base OIDC provider using discovery, token exchange, and JWKS validation."""

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str = "",
        auth_endpoint: str | None = None,
        token_endpoint: str | None = None,
        userinfo_endpoint: str | None = None,
        jwks_uri: str | None = None,
        logout_endpoint: str | None = None,
        claims_namespace: str = "https://example.com/claims",
        discovery_url: str | None = None,
        timeout_seconds: float = 10.0,
        verify_ssl: bool = True,
        jwks_cache_ttl_seconds: int = 3600,
    ) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.jwks_uri = jwks_uri
        self.logout_endpoint = logout_endpoint
        self.claims_namespace = claims_namespace
        self.discovery_url = discovery_url
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        self.jwks_cache_ttl_seconds = jwks_cache_ttl_seconds
        self._discovery_cache: _DiscoveryCache | None = None
        self._jwk_client: jwt.PyJWKClient | None = None

    @staticmethod
    def _derive_code_challenge(code_verifier: str) -> str:
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    @classmethod
    def create_auth_context(cls) -> OIDCAuthContext:
        """Create auth context."""
        verifier = secrets.token_urlsafe(64)
        if len(verifier) > 128:
            verifier = verifier[:128]
        return OIDCAuthContext(
            state=secrets.token_urlsafe(24),
            nonce=secrets.token_urlsafe(24),
            code_verifier=verifier,
            code_challenge=cls._derive_code_challenge(verifier),
        )

    @staticmethod
    def extract_callback_params(callback_url: str) -> dict[str, str]:
        """Handle extract callback params."""
        parsed = urlparse(callback_url)
        query = parse_qs(parsed.query)
        return {k: v[0] for k, v in query.items() if v}

    @staticmethod
    def validate_callback(
        params: dict[str, str], *, expected_state: str
    ) -> tuple[str, str | None]:
        """Validate callback."""
        code = params.get("code")
        returned_state = params.get("state")
        if not code:
            raise ValueError("Missing code in callback parameters")
        if not returned_state or returned_state != expected_state:
            raise ValueError("Invalid callback state")
        return code, params.get("error")

    async def _load_discovery(self) -> dict[str, Any]:
        now = time.time()
        if self._discovery_cache and now < self._discovery_cache.expires_at:
            return self._discovery_cache.document
        if not self.discovery_url:
            return {}
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, verify=self.verify_ssl
        ) as client:
            response = await client.get(self.discovery_url)
        response.raise_for_status()
        document = response.json()
        self._discovery_cache = _DiscoveryCache(
            document=document,
            expires_at=now + self.jwks_cache_ttl_seconds,
        )
        return document

    async def _resolve_endpoints(self) -> None:
        discovery = await self._load_discovery()
        self.auth_endpoint = self.auth_endpoint or discovery.get(
            "authorization_endpoint"
        )
        self.token_endpoint = self.token_endpoint or discovery.get("token_endpoint")
        self.userinfo_endpoint = self.userinfo_endpoint or discovery.get(
            "userinfo_endpoint"
        )
        self.jwks_uri = self.jwks_uri or discovery.get("jwks_uri")
        self.logout_endpoint = self.logout_endpoint or discovery.get(
            "end_session_endpoint"
        )

    def create_authorization_session(
        self,
        *,
        redirect_uri: str,
        scope: str = "openid email profile",
        response_type: str = "code",
        extra_params: dict[str, str] | None = None,
    ) -> OIDCAuthorizationSession:
        """Create authorization session."""
        ctx = self.create_auth_context()
        params = dict(extra_params or {})
        authorization_url = self.get_authorization_url(
            state=ctx.state,
            nonce=ctx.nonce,
            redirect_uri=redirect_uri,
            scope=scope,
            response_type=response_type,
            code_challenge=ctx.code_challenge,
            code_challenge_method="S256",
            **params,
        )
        return OIDCAuthorizationSession(
            authorization_url=authorization_url, context=ctx
        )

    def get_authorization_url(self, state: str, nonce: str, **kwargs) -> str:
        """Return authorization url."""
        if not self.auth_endpoint:
            raise ValueError("authorisation endpoint not configured")
        query = {
            "client_id": self.client_id,
            "response_type": kwargs.get("response_type", "code"),
            "scope": kwargs.get("scope", "openid email profile"),
            "state": state,
            "nonce": nonce,
            "redirect_uri": kwargs.get("redirect_uri", ""),
        }
        code_challenge = kwargs.get("code_challenge")
        if code_challenge:
            query["code_challenge"] = code_challenge
            query["code_challenge_method"] = kwargs.get("code_challenge_method", "S256")
        return f"{self.auth_endpoint}?{urlencode(query)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenSet:
        """Handle exchange code."""
        await self._resolve_endpoints()
        if not self.token_endpoint:
            raise ValueError("token endpoint not configured")
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        if code_verifier:
            payload["code_verifier"] = code_verifier
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, verify=self.verify_ssl
        ) as client:
            response = await client.post(self.token_endpoint, data=payload)
        response.raise_for_status()
        body = response.json()
        return TokenSet(
            access_token=body["access_token"],
            id_token=body.get("id_token"),
            refresh_token=body.get("refresh_token"),
            expires_in=int(body.get("expires_in", 3600)),
        )

    async def get_userinfo(self, access_token: str) -> UserInfo:
        """Return userinfo."""
        await self._resolve_endpoints()
        if not self.userinfo_endpoint:
            raise ValueError("userinfo endpoint not configured")
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, verify=self.verify_ssl
        ) as client:
            response = await client.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        response.raise_for_status()
        body = response.json()
        return UserInfo(
            sub=str(body.get("sub", "")),
            email=body.get("email"),
            name=body.get("name"),
            claims=body,
        )

    async def refresh_token(self, refresh_token: str) -> TokenSet:
        """Refresh token."""
        await self._resolve_endpoints()
        if not self.token_endpoint:
            raise ValueError("token endpoint not configured")
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, verify=self.verify_ssl
        ) as client:
            response = await client.post(self.token_endpoint, data=payload)
        response.raise_for_status()
        body = response.json()
        return TokenSet(
            access_token=body["access_token"],
            id_token=body.get("id_token"),
            refresh_token=body.get("refresh_token", refresh_token),
            expires_in=int(body.get("expires_in", 3600)),
        )

    def map_claims_to_user(self, claims: dict) -> dict:
        """Handle map claims to user."""
        return {
            "username": claims.get("preferred_username")
            or claims.get("email")
            or claims.get("sub"),
            "email": claims.get("email", ""),
            "display_name": claims.get("name") or claims.get("given_name") or "",
        }

    def map_claims_to_roles(self, claims: dict) -> list[str]:
        """Handle map claims to roles."""
        realm_roles = (claims.get("realm_access") or {}).get("roles") or []
        client_roles = []
        resource_access = claims.get("resource_access") or {}
        if self.client_id in resource_access:
            client_roles = (resource_access[self.client_id] or {}).get("roles") or []
        namespaced_roles = claims.get(f"{self.claims_namespace}/roles", [])
        ordered: list[str] = []
        for role in [*client_roles, *realm_roles, *namespaced_roles]:
            if role not in ordered:
                ordered.append(role)
        return ordered

    async def validate_id_token(
        self, id_token: str, *, expected_nonce: str | None = None
    ) -> dict:
        """Validate id token."""
        await self._resolve_endpoints()
        if not self.jwks_uri:
            raise ValueError("jwks_uri not configured")
        if self._jwk_client is None:
            self._jwk_client = jwt.PyJWKClient(self.jwks_uri)
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(id_token)
        except PyJWKClientError:
            # Key rotation path: refresh JWKS client and retry once.
            self._jwk_client = jwt.PyJWKClient(self.jwks_uri)
            signing_key = self._jwk_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256"],
            audience=self.client_id,
            issuer=self.issuer,
        )
        if expected_nonce and claims.get("nonce") != expected_nonce:
            raise ValueError("Invalid token nonce")
        return claims

    def get_logout_url(self, **kwargs) -> str | None:
        """Return logout url."""
        if not self.logout_endpoint:
            return None
        return_to = kwargs.get("return_to", "")
        query = {"client_id": self.client_id}
        if return_to:
            query["returnTo"] = return_to
        return f"{self.logout_endpoint}?{urlencode(query)}"


class KeycloakProvider(BasicOIDCProvider):
    """Represent keycloak provider."""
    def __init__(
        self,
        *,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str = "",
        timeout_seconds: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        prefix = f"{base_url.rstrip('/')}/realms/{realm}"
        super().__init__(
            issuer=prefix,
            client_id=client_id,
            client_secret=client_secret,
            auth_endpoint=f"{prefix}/protocol/openid-connect/auth",
            token_endpoint=f"{prefix}/protocol/openid-connect/token",
            userinfo_endpoint=f"{prefix}/protocol/openid-connect/userinfo",
            jwks_uri=f"{prefix}/protocol/openid-connect/certs",
            logout_endpoint=f"{prefix}/protocol/openid-connect/logout",
            discovery_url=f"{prefix}/.well-known/openid-configuration",
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
        )


class Auth0Provider(BasicOIDCProvider):
    """Represent auth0 provider."""
    def __init__(
        self,
        *,
        domain: str,
        client_id: str,
        client_secret: str = "",
        claims_namespace: str = "https://example.com/claims",
        timeout_seconds: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        base = f"https://{domain}"
        super().__init__(
            issuer=f"{base}/",
            client_id=client_id,
            client_secret=client_secret,
            claims_namespace=claims_namespace,
            auth_endpoint=f"{base}/authorize",
            token_endpoint=f"{base}/oauth/token",
            userinfo_endpoint=f"{base}/userinfo",
            jwks_uri=f"{base}/.well-known/jwks.json",
            discovery_url=f"{base}/.well-known/openid-configuration",
            logout_endpoint=f"{base}/v2/logout",
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
        )

    async def get_m2m_token(self, audience: str) -> TokenSet:
        """Return m2m token."""
        await self._resolve_endpoints()
        if not self.token_endpoint:
            raise ValueError("token endpoint not configured")
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": audience,
        }
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, verify=self.verify_ssl
        ) as client:
            response = await client.post(self.token_endpoint, json=payload)
        response.raise_for_status()
        body = response.json()
        return TokenSet(
            access_token=body["access_token"],
            expires_in=int(body.get("expires_in", 3600)),
        )


class GoogleProvider(BasicOIDCProvider):
    """Represent google provider."""
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str = "",
        hosted_domain: str = "",
        timeout_seconds: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        super().__init__(
            issuer="https://accounts.google.com",
            client_id=client_id,
            client_secret=client_secret,
            auth_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
        )
        self._hosted_domain = hosted_domain

    def map_claims_to_roles(self, claims: dict) -> list[str]:
        """Handle map claims to roles."""
        if not claims.get("email_verified", True):
            return []
        if self._hosted_domain and claims.get("hd") != self._hosted_domain:
            return []
        email = str(claims.get("email", "")).lower()
        if self._hosted_domain and email.endswith(f"@{self._hosted_domain.lower()}"):
            return ["admin"]
        return ["viewer"]


class LinkedInProvider(BasicOIDCProvider):
    """Represent linked in provider."""
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str = "",
        timeout_seconds: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        super().__init__(
            issuer="https://www.linkedin.com",
            client_id=client_id,
            client_secret=client_secret,
            discovery_url="https://www.linkedin.com/oauth/.well-known/openid-configuration",
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
        )
