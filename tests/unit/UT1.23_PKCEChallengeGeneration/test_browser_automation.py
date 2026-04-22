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

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from cloud_dog_idam.providers.browser_automation import (
    BrowserCredentials,
    OIDCBrowserAutomation,
    callback_host,
)
from cloud_dog_idam.providers.oidc import Auth0Provider, GoogleProvider, TokenSet


@pytest.mark.asyncio
async def test_auth0_browser_callback_automation_mocked() -> None:
    state_holder: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/authorize":
            params = parse_qs(request.url.query.decode())
            state_holder["state"] = params["state"][0]
            html = (
                '<form action="/u/login/password" method="post">'
                '<input type="hidden" name="state" value="abc"/>'
                '<input type="text" name="username"/>'
                '<input type="password" name="password"/>'
                "</form>"
            )
            return httpx.Response(200, text=html)
        if request.method == "POST" and request.url.path == "/u/login/password":
            body = request.content.decode()
            assert "username=user%40example.com" in body
            assert "password=secret" in body
            location = (
                "https://app.example.com/callback"
                f"?code=auth0-code&state={state_holder['state']}"
            )
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(404)

    provider = Auth0Provider(
        domain="tenant.example.com",
        client_id="client-id",
        client_secret="client-secret",
        verify_ssl=False,
    )
    automation = OIDCBrowserAutomation(
        provider, verify_ssl=False, transport=httpx.MockTransport(handler)
    )
    result = await automation.authenticate_auth0(
        BrowserCredentials(username="user@example.com", password="secret"),
        redirect_uri="https://app.example.com/callback",
    )
    assert result.code == "auth0-code"
    assert callback_host(result.callback_url) == "app.example.com"


@pytest.mark.asyncio
async def test_google_browser_callback_automation_mocked() -> None:
    state_holder: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/o/oauth2/v2/auth":
            params = parse_qs(request.url.query.decode())
            state_holder["state"] = params["state"][0]
            html = (
                '<form action="/signin/v2/identifier" method="post">'
                '<input type="hidden" name="flowName" value="GlifWebSignIn"/>'
                '<input type="text" name="identifier"/>'
                "</form>"
            )
            return httpx.Response(200, text=html)
        if request.method == "POST" and request.url.path == "/signin/v2/identifier":
            body = request.content.decode()
            assert "identifier=user%40gmail.com" in body
            html = (
                '<form action="/signin/v2/challenge/pwd" method="post">'
                '<input type="hidden" name="continue" value="/"/>'
                '<input type="password" name="Passwd"/>'
                "</form>"
            )
            return httpx.Response(200, text=html)
        if request.method == "POST" and request.url.path == "/signin/v2/challenge/pwd":
            body = request.content.decode()
            assert "Passwd=secret" in body
            location = (
                "https://app.example.com/google-callback"
                f"?code=google-code&state={state_holder['state']}"
            )
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(404)

    provider = GoogleProvider(client_id="google-client", client_secret="google-secret")
    automation = OIDCBrowserAutomation(
        provider, transport=httpx.MockTransport(handler), verify_ssl=False
    )
    result = await automation.authenticate_google(
        BrowserCredentials(username="user@example.com", password="secret"),
        redirect_uri="https://app.example.com/google-callback",
    )
    parsed = urlparse(result.callback_url)
    assert parsed.path == "/google-callback"
    assert result.code == "google-code"


@pytest.mark.asyncio
async def test_interactive_helper_start_and_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = Auth0Provider(
        domain="tenant.example.com",
        client_id="client-id",
        client_secret="client-secret",
        verify_ssl=False,
    )
    automation = OIDCBrowserAutomation(provider)
    flow = automation.start_interactive_auth(
        redirect_uri="https://app.example.com/callback",
        provider_name="auth0",
        open_browser=False,
    )
    assert flow.provider == "auth0"
    assert "code_challenge=" in flow.authorization_url

    async def fake_exchange_code(
        code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenSet:
        assert code == "interactive-code"
        assert redirect_uri == flow.redirect_uri
        assert code_verifier == flow.code_verifier
        return TokenSet(
            access_token="access-token",
            id_token="id-token",
            refresh_token="refresh-token",
            expires_in=3600,
        )

    async def fake_validate_id_token(
        id_token: str, *, expected_nonce: str | None = None
    ) -> dict[str, str]:
        assert id_token == "id-token"
        assert expected_nonce == flow.nonce
        return {"sub": "user-1", "nonce": flow.nonce}

    monkeypatch.setattr(provider, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(provider, "validate_id_token", fake_validate_id_token)

    callback_url = (
        f"https://app.example.com/callback?code=interactive-code&state={flow.state}"
    )
    result = await automation.complete_interactive_callback(
        callback_url=callback_url, flow=flow
    )
    assert result["access_token"] == "access-token"
    assert result["refresh_token"] == "refresh-token"
    assert result["claims"] == {"sub": "user-1", "nonce": flow.nonce}
