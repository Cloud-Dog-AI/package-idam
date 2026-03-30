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

# cloud_dog_idam — OIDC browser automation helpers
"""Browser-driven OIDC callback automation for embedded application flows."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import webbrowser

from cloud_dog_idam.providers.oidc import BasicOIDCProvider


class BrowserAutomationError(RuntimeError):
    """Raised when an interactive browser login flow cannot be completed."""


@dataclass(slots=True)
class BrowserCredentials:
    """Represent browser credentials."""
    username: str
    password: str


@dataclass(slots=True)
class BrowserFlowResult:
    """Represent browser flow result."""
    callback_url: str
    code: str
    state: str
    nonce: str
    code_verifier: str
    error: str | None = None


@dataclass(slots=True)
class InteractiveAuthStart:
    """Represent interactive auth start."""
    provider: str
    authorization_url: str
    redirect_uri: str
    state: str
    nonce: str
    code_verifier: str


@dataclass(slots=True)
class HTMLForm:
    """Represent h t m l form."""
    action: str
    method: str
    fields: dict[str, str]


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[HTMLForm] = []
        self._form_stack: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Handle handle starttag."""
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self._form_stack.append(
                {
                    "action": attr_map.get("action", ""),
                    "method": attr_map.get("method", "post").upper(),
                    "fields": {},
                }
            )
            return
        if tag == "input" and self._form_stack:
            name = attr_map.get("name", "")
            if not name:
                return
            value = attr_map.get("value", "")
            self._form_stack[-1]["fields"][name] = value

    def handle_endtag(self, tag: str) -> None:
        """Handle handle endtag."""
        if tag.lower() != "form":
            return
        if not self._form_stack:
            return
        item = self._form_stack.pop()
        self.forms.append(
            HTMLForm(
                action=item["action"],
                method=item["method"],
                fields=dict(item["fields"]),
            )
        )


class OIDCBrowserAutomation:
    """Executes provider-specific browser login and callback code retrieval."""

    def __init__(
        self,
        provider: BasicOIDCProvider,
        *,
        timeout_seconds: float = 20.0,
        verify_ssl: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._provider = provider
        self._timeout_seconds = timeout_seconds
        self._verify_ssl = verify_ssl
        self._transport = transport

    @staticmethod
    def _parse_forms(html: str) -> list[HTMLForm]:
        parser = _FormParser()
        parser.feed(html)
        return parser.forms

    @staticmethod
    def _resolve_action(base_url: str, action: str) -> str:
        return urljoin(base_url, action)

    async def _request(
        self,
        client: httpx.AsyncClient,
        *,
        method: str,
        url: str,
        data: dict[str, str] | None = None,
    ) -> httpx.Response:
        if method.upper() == "GET":
            return await client.get(url)
        return await client.post(
            url,
            data=data or {},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    async def _finish_callback(
        self,
        client: httpx.AsyncClient,
        response: httpx.Response,
        *,
        redirect_uri: str,
        expected_state: str,
        nonce: str,
        code_verifier: str,
    ) -> BrowserFlowResult:
        current = response
        redirect_target = current.headers.get("location", "")
        for _ in range(8):
            if current.status_code not in {302, 303} or not redirect_target:
                break
            absolute = self._resolve_action(str(current.url), redirect_target)
            if absolute.startswith(redirect_uri):
                redirect_target = absolute
                break
            current = await client.get(absolute)
            redirect_target = current.headers.get("location", "")
        if not redirect_target or not redirect_target.startswith(redirect_uri):
            raise BrowserAutomationError(
                f"Unexpected callback target: {redirect_target or str(current.url)}"
            )
        params = self._provider.extract_callback_params(redirect_target)
        code, error = self._provider.validate_callback(
            params, expected_state=expected_state
        )
        if error:
            raise BrowserAutomationError(f"Callback returned error: {error}")
        return BrowserFlowResult(
            callback_url=redirect_target,
            code=code,
            state=expected_state,
            nonce=nonce,
            code_verifier=code_verifier,
            error=error,
        )

    async def authenticate_auth0(
        self,
        credentials: BrowserCredentials,
        *,
        redirect_uri: str,
        scope: str = "openid email profile",
        extra_authorize_params: dict[str, str] | None = None,
    ) -> BrowserFlowResult:
        """Handle authenticate auth0."""
        ctx = self._provider.create_auth_context()
        params = dict(extra_authorize_params or {})
        auth_url = self._provider.get_authorization_url(
            state=ctx.state,
            nonce=ctx.nonce,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=ctx.code_challenge,
            code_challenge_method="S256",
            **params,
        )
        async with httpx.AsyncClient(
            timeout=self._timeout_seconds,
            verify=self._verify_ssl,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            page = await client.get(auth_url)
            if page.status_code in {302, 303} and page.headers.get("location"):
                page = await client.get(
                    self._resolve_action(str(page.url), page.headers["location"])
                )
            forms = self._parse_forms(page.text)
            if not forms:
                raise BrowserAutomationError("No Auth0 login form found")
            form = forms[0]
            action = self._resolve_action(str(page.url), form.action)
            fields = dict(form.fields)
            # Auth0 universal login supports identifier and password fields.
            fields["username"] = credentials.username
            fields["email"] = credentials.username
            fields["password"] = credentials.password
            response = await self._request(
                client, method=form.method, url=action, data=fields
            )
            return await self._finish_callback(
                client,
                response,
                redirect_uri=redirect_uri,
                expected_state=ctx.state,
                nonce=ctx.nonce,
                code_verifier=ctx.code_verifier,
            )

    async def authenticate_google(
        self,
        credentials: BrowserCredentials,
        *,
        redirect_uri: str,
        scope: str = "openid email profile",
        extra_authorize_params: dict[str, str] | None = None,
    ) -> BrowserFlowResult:
        """Handle authenticate google."""
        ctx = self._provider.create_auth_context()
        params = dict(extra_authorize_params or {})
        params.setdefault("prompt", "consent")
        params.setdefault("access_type", "offline")
        auth_url = self._provider.get_authorization_url(
            state=ctx.state,
            nonce=ctx.nonce,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=ctx.code_challenge,
            code_challenge_method="S256",
            **params,
        )
        async with httpx.AsyncClient(
            timeout=self._timeout_seconds,
            verify=self._verify_ssl,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            identifier_page = await client.get(auth_url)
            if identifier_page.status_code in {
                302,
                303,
            } and identifier_page.headers.get("location"):
                identifier_page = await client.get(
                    self._resolve_action(
                        str(identifier_page.url), identifier_page.headers["location"]
                    )
                )
            forms = self._parse_forms(identifier_page.text)
            if not forms:
                raise BrowserAutomationError("No Google identifier form found")
            identifier_form = forms[0]
            identifier_action = self._resolve_action(
                str(identifier_page.url), identifier_form.action
            )
            identifier_fields = dict(identifier_form.fields)
            identifier_fields["identifier"] = credentials.username
            identifier_fields["Email"] = credentials.username
            password_page = await self._request(
                client,
                method=identifier_form.method,
                url=identifier_action,
                data=identifier_fields,
            )
            pw_forms = self._parse_forms(password_page.text)
            if not pw_forms:
                raise BrowserAutomationError("No Google password form found")
            password_form = pw_forms[0]
            password_action = self._resolve_action(
                str(password_page.url), password_form.action
            )
            password_fields = dict(password_form.fields)
            password_fields["Passwd"] = credentials.password
            password_fields["password"] = credentials.password
            callback_response = await self._request(
                client,
                method=password_form.method,
                url=password_action,
                data=password_fields,
            )
            return await self._finish_callback(
                client,
                callback_response,
                redirect_uri=redirect_uri,
                expected_state=ctx.state,
                nonce=ctx.nonce,
                code_verifier=ctx.code_verifier,
            )

    async def exchange_callback(
        self, result: BrowserFlowResult, *, redirect_uri: str
    ) -> dict[str, str]:
        """Handle exchange callback."""
        token_set = await self._provider.exchange_code(
            code=result.code,
            redirect_uri=redirect_uri,
            code_verifier=result.code_verifier,
        )
        return {
            "access_token": token_set.access_token,
            "id_token": token_set.id_token or "",
            "refresh_token": token_set.refresh_token or "",
        }

    def start_interactive_auth(
        self,
        *,
        redirect_uri: str,
        scope: str = "openid email profile",
        provider_name: str = "oidc",
        extra_authorize_params: dict[str, str] | None = None,
        open_browser: bool = False,
    ) -> InteractiveAuthStart:
        """Handle start interactive auth."""
        session = self._provider.create_authorization_session(
            redirect_uri=redirect_uri,
            scope=scope,
            extra_params=extra_authorize_params,
        )
        if open_browser:
            webbrowser.open(session.authorization_url)
        return InteractiveAuthStart(
            provider=provider_name,
            authorization_url=session.authorization_url,
            redirect_uri=redirect_uri,
            state=session.context.state,
            nonce=session.context.nonce,
            code_verifier=session.context.code_verifier,
        )

    async def complete_interactive_callback(
        self,
        *,
        callback_url: str,
        flow: InteractiveAuthStart,
        validate_id_token: bool = True,
    ) -> dict[str, str | dict[str, Any]]:
        """Handle complete interactive callback."""
        params = self._provider.extract_callback_params(callback_url)
        code, error = self._provider.validate_callback(
            params, expected_state=flow.state
        )
        if error:
            raise BrowserAutomationError(f"Callback returned error: {error}")
        token_set = await self._provider.exchange_code(
            code=code,
            redirect_uri=flow.redirect_uri,
            code_verifier=flow.code_verifier,
        )
        result: dict[str, str | dict[str, Any]] = {
            "access_token": token_set.access_token,
            "id_token": token_set.id_token or "",
            "refresh_token": token_set.refresh_token or "",
        }
        if validate_id_token and token_set.id_token:
            claims = await self._provider.validate_id_token(
                token_set.id_token, expected_nonce=flow.nonce
            )
            result["claims"] = claims
        return result


def callback_host(url: str) -> str:
    """Return callback host for diagnostics and policy checks."""
    return urlparse(url).netloc
