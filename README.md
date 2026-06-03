# platform-idam

**Package:** `cloud_dog_idam`  
**Standard:** PS-70 (User Management & IDAM)  
**Status:** Implemented, validated, build-ready (`v0.2.0`)

## Purpose

Drop-in Python library implementing the PS-70 IDAM standard. Provides pluggable authentication providers, RBAC with permissions, API key management, token/session handling, and mandatory audit logging.

## Key Features

- **Authentication providers**: Local password (Argon2id), API key, JWT Bearer, OIDC (Keycloak/Auth0/Google), LDAP/AD, SAML, OS/PAM
- **RBAC**: Users → Groups → Roles → Permissions; external RBAC sources (LDAP/Keycloak); caching
- **API keys**: Hash-only storage, shown once, rotate, revoke, expire, system users
- **Tokens**: JWT (stateless) or opaque (instant revocation); refresh tokens; configurable TTL
- **Identity linking**: Multiple external identities per user; JIT provisioning
- **Approval workflows**: `pending_approval` → admin approval → active
- **Security controls**: Password policy, lockout, TOTP/MFA, rate limiting (all configurable)
- **Audit**: Mandatory append-only events for all security actions
- **FastAPI integration**: Optional auth routers + `require_permission(...)` dependency
- **Database**: SQLAlchemy models + Alembic migrations

## Dependencies

- **Required:** `sqlalchemy`, `alembic`, `argon2-cffi`, `pyjwt`, `cryptography`
- **Optional:** `python-ldap`, `authlib`, `pysaml2`, `pyotp`

## Documents

- [REQUIREMENTS.md](REQUIREMENTS.md) — Functional and non-functional requirements (30 FRs)
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module layout, component design, data model, integration pattern
- [TESTS.md](TESTS.md) — Test plan, directory structure, coverage map (UT/ST/IT/AT/QT)
- [QUALITY-GATE.md](QUALITY-GATE.md) — Gap closure and verification evidence

## Validation Snapshot (2026-02-18)

- `./.venv/bin/ruff check cloud_dog_idam tests` — pass
- `./.venv/bin/ruff format --check cloud_dog_idam tests` — `145 files already formatted`
- `./.venv/bin/pytest tests -q --env UT --env ST --env IT --env AT --env QT --env <your-vault-env-file>` — `83 passed, 0 skipped`
- `./.venv/bin/python -m build --no-isolation` — wheel + sdist generated
- `./.venv/bin/pip install --force-reinstall --no-deps dist/cloud_dog_idam-0.2.0-py3-none-any.whl` + import check — pass

## Quick Start (planned)

```python
from cloud_dog_idam import IDAMManager
from cloud_dog_idam.providers import LocalPasswordProvider, APIKeyProvider
from cloud_dog_idam.api.fastapi import auth_router, require_permission

idam = IDAMManager(db_session=db, config=config)
idam.register_provider(LocalPasswordProvider(db))
idam.register_provider(APIKeyProvider(db))

app.include_router(auth_router)

@app.get("/admin/users")
async def list_users(user=Depends(require_permission("users:read"))):
    return await idam.users.list()
```

## Embedded Browser Callback Helpers

`cloud_dog_idam` now includes embeddable browser automation helpers for provider login callback completion:

- `cloud_dog_idam.providers.OIDCBrowserAutomation`
- `cloud_dog_idam.providers.BrowserCredentials`
- `cloud_dog_idam.providers.BrowserFlowResult`
- `cloud_dog_idam.providers.InteractiveAuthStart` (2FA/manual web flow support)

Example:

```python
from cloud_dog_idam.providers import Auth0Provider
from cloud_dog_idam.providers import BrowserCredentials, OIDCBrowserAutomation

provider = Auth0Provider(domain="tenant.auth0.com", client_id="...", client_secret="...")
browser = OIDCBrowserAutomation(provider, verify_ssl=False)
flow = await browser.authenticate_auth0(
    BrowserCredentials(username="user@example.com", password="secret"),
    redirect_uri="https://app.example.com/callback",
)
tokens = await provider.exchange_code(
    flow.code,
    redirect_uri="https://app.example.com/callback",
    code_verifier=flow.code_verifier,
)
```

For 2FA-enabled users, use interactive mode:

```python
flow = browser.start_interactive_auth(
    redirect_uri="http://localhost:8000/auth/auth0/callback",
    provider_name="auth0",
    open_browser=True,
)
# user completes login + 2FA in browser, then paste callback URL:
result = await browser.complete_interactive_callback(
    callback_url=pasted_callback_url,
    flow=flow,
)
```

## Installation

```bash
pip install cloud-dog-idam
```

## API Overview

- token services issue and validate auth artefacts
- repositories and services manage users, groups, roles, and policy checks
- provider adapters integrate OIDC, LDAP, SAML, PAM, and MFA flows

## Examples

- Issue a token for an authenticated principal.
- Build unit-test identities with the testing fixture helpers.

---

## Licence

Apache-2.0 — Copyright (c) 2026 Cloud-Dog, Viewdeck Engineering Limited
