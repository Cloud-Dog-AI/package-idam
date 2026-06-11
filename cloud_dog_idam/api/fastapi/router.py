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

# cloud_dog_idam — FastAPI routers
"""Auth and CRUD routers for users, groups, roles, and API keys."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException

from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.domain.models import Group, RBACBinding, Role, User
from cloud_dog_idam.rbac.resource_registry import ResourceRegistryService
from cloud_dog_idam.users.groups import GroupService
from cloud_dog_idam.users.roles import RoleService
from cloud_dog_idam.users.service import UserService


auth_router = APIRouter(prefix="/auth", tags=["auth"])
user_router = APIRouter(prefix="/users", tags=["users"])
group_router = APIRouter(prefix="/groups", tags=["groups"])
role_router = APIRouter(prefix="/roles", tags=["roles"])
api_key_router = APIRouter(prefix="/api-keys", tags=["api_keys"])
idam_v1_router = APIRouter(prefix="/idam/v1", tags=["idam"])

_users = UserService()
_groups = GroupService()
_roles = RoleService()
_keys = APIKeyManager()
_resource_registry = ResourceRegistryService()


@auth_router.get("/health")
async def auth_health() -> dict[str, str]:
    """Handle auth health."""
    return {"status": "ok"}


@auth_router.post("/login")
async def auth_login(payload: dict) -> dict:
    """Handle auth login."""
    username = str(payload.get("username", ""))
    for user in _users.list():
        if user.username == username:
            return {"ok": True, "user_id": user.user_id}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@auth_router.post("/logout")
async def auth_logout() -> dict[str, bool]:
    """Handle auth logout."""
    return {"ok": True}


@auth_router.post("/token/refresh")
async def auth_refresh() -> dict[str, str]:
    """Handle auth refresh."""
    return {"token": "refreshed"}


@auth_router.get("/oidc/{provider}/login")
async def auth_oidc_login(provider: str) -> dict[str, str]:
    """Handle auth oidc login."""
    return {"provider": provider, "status": "redirect"}


@auth_router.get("/oidc/{provider}/callback")
async def auth_oidc_callback(provider: str) -> dict[str, str]:
    """Handle auth oidc callback."""
    return {"provider": provider, "status": "callback_processed"}


@auth_router.get("/saml/metadata")
async def auth_saml_metadata() -> dict[str, str]:
    """Handle auth saml metadata."""
    return {"metadata": "<xml/>"}


@auth_router.post("/saml/acs")
async def auth_saml_acs() -> dict[str, str]:
    """Handle auth saml acs."""
    return {"status": "acs_processed"}


@user_router.post("")
async def create_user(payload: dict) -> dict:
    """Create user."""
    user = _users.create(
        User(
            username=str(payload.get("username", "")),
            email=str(payload.get("email", "")),
        )
    )
    return asdict(user)


@user_router.get("")
async def list_users() -> list[dict]:
    """List users."""
    return [asdict(u) for u in _users.list()]


@user_router.get("/{user_id}")
async def get_user(user_id: str) -> dict:
    """Return user."""
    user = _users.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    return asdict(user)


@user_router.patch("/{user_id}")
async def update_user(user_id: str, payload: dict) -> dict:
    """Update user."""
    try:
        user = _users.update(user_id, **payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Not found") from exc
    return asdict(user)


@user_router.delete("/{user_id}")
async def delete_user(user_id: str) -> dict[str, bool]:
    """Delete user."""
    return {"ok": _users.disable(user_id)}


@user_router.get("/{user_id}/identities")
async def user_identities(user_id: str) -> list[dict]:
    """Handle user identities."""
    return []


@user_router.get("/{user_id}/roles")
async def user_roles(user_id: str) -> list[str]:
    """Handle user roles."""
    return sorted(_roles.get_assigned(user_id))


@user_router.get("/{user_id}/groups")
async def user_groups(user_id: str) -> list[str]:
    """Handle user groups."""
    return [
        g.group_id for g in _groups.list() if user_id in _groups.members(g.group_id)
    ]


@group_router.post("")
async def create_group(payload: dict) -> dict:
    """Create group."""
    group = _groups.create(
        Group(
            name=str(payload.get("name", "")),
            description=str(payload.get("description", "")),
        )
    )
    return asdict(group)


@group_router.get("")
async def list_groups() -> list[dict]:
    """List groups."""
    return [asdict(g) for g in _groups.list()]


@group_router.get("/{group_id}")
async def get_group(group_id: str) -> dict:
    """Return group."""
    for g in _groups.list():
        if g.group_id == group_id:
            return asdict(g)
    raise HTTPException(status_code=404, detail="Not found")


@group_router.patch("/{group_id}")
async def update_group(group_id: str, payload: dict) -> dict:
    """Update group."""
    for g in _groups.list():
        if g.group_id == group_id:
            if "name" in payload:
                g.name = str(payload["name"])
            if "description" in payload:
                g.description = str(payload["description"])
            return asdict(g)
    raise HTTPException(status_code=404, detail="Not found")


@group_router.delete("/{group_id}")
async def delete_group(group_id: str) -> dict[str, bool]:
    """Delete group."""
    before = len(_groups.list())
    _groups._groups.pop(group_id, None)
    return {"ok": len(_groups.list()) != before}


@group_router.post("/{group_id}/members")
async def add_group_member(group_id: str, payload: dict) -> dict[str, bool]:
    """Handle add group member."""
    _groups.add_member(group_id, str(payload.get("user_id", "")))
    return {"ok": True}


@group_router.delete("/{group_id}/members/{user_id}")
async def remove_group_member(group_id: str, user_id: str) -> dict[str, bool]:
    """Handle remove group member."""
    members = _groups._members.get(group_id, set())
    members.discard(user_id)
    return {"ok": True}


@role_router.post("")
async def create_role(payload: dict) -> dict:
    """Create role."""
    role = _roles.create(
        Role(
            name=str(payload.get("name", "")),
            description=str(payload.get("description", "")),
        )
    )
    return asdict(role)


@role_router.get("")
async def list_roles() -> list[dict]:
    """List roles."""
    return [asdict(r) for r in _roles.list()]


@role_router.get("/{role_id}")
async def get_role(role_id: str) -> dict:
    """Return role."""
    for role in _roles.list():
        if role.role_id == role_id:
            return asdict(role)
    raise HTTPException(status_code=404, detail="Not found")


@role_router.patch("/{role_id}")
async def update_role(role_id: str, payload: dict) -> dict:
    """Update role."""
    for role in _roles.list():
        if role.role_id == role_id:
            if "name" in payload:
                role.name = str(payload["name"])
            if "description" in payload:
                role.description = str(payload["description"])
            return asdict(role)
    raise HTTPException(status_code=404, detail="Not found")


@role_router.delete("/{role_id}")
async def delete_role(role_id: str) -> dict[str, bool]:
    """Delete role."""
    before = len(_roles.list())
    _roles._roles.pop(role_id, None)
    return {"ok": len(_roles.list()) != before}


@role_router.post("/{role_id}/permissions")
async def add_role_permission(role_id: str, payload: dict) -> dict[str, bool]:
    """Handle add role permission."""
    for role in _roles.list():
        if role.role_id == role_id:
            role.permissions.add(str(payload.get("permission", "")))
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Not found")


@role_router.delete("/{role_id}/permissions/{permission_id}")
async def remove_role_permission(role_id: str, permission_id: str) -> dict[str, bool]:
    """Handle remove role permission."""
    for role in _roles.list():
        if role.role_id == role_id:
            role.permissions.discard(permission_id)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Not found")


@api_key_router.post("")
async def create_api_key(payload: dict) -> dict:
    """Create api key."""
    owner_user_id = str(payload.get("owner_user_id", "system"))
    raw, meta = _keys.generate(owner_user_id)
    return {"raw_key": raw, "api_key_id": meta.api_key_id}


@api_key_router.get("")
async def list_api_keys(owner_user_id: str) -> list[dict]:
    """List api keys."""
    return [asdict(k) for k in _keys.list_keys(owner_user_id)]


@api_key_router.post("/{key_id}/rotate")
async def rotate_api_key(key_id: str) -> dict:
    """Handle rotate api key."""
    raw, meta = _keys.rotate(key_id)
    return {"raw_key": raw, "api_key_id": meta.api_key_id}


@api_key_router.delete("/{key_id}")
async def revoke_api_key(key_id: str) -> dict[str, bool]:
    """Handle revoke api key."""
    return {"ok": _keys.revoke(key_id)}


@idam_v1_router.get("/resource-registry")
async def resource_registry(project: str | None = None) -> dict:
    """Return the PS-71 resource-registry response shape."""
    return _resource_registry.to_response(project=project)


# W28A-741: D-NO-BINDING-1 — the binding write API per IDAM-B2 §4.1 step 5 +
# idam-canonical-model-map.md canonical route /idam/v1/rbac/bindings.
#
# The in-memory ``_bindings`` store below is the keystone reference surface.
# Production host applications SHOULD replace the store with an injected
# ``RBACBindingRepository`` over the existing ``rbac_bindings`` SQLAlchemy
# table; the canonical model map confirms that table + ORM exist with the
# correct schema (no schema change). This router exposes the WIRE CONTRACT
# (the routes + payload shape) the WebUI / CLI / agents call. Host
# applications override the store + add their own guard wiring (the
# resource-aware ``require_permission`` from ``deps.py``) at app-mount time.
_bindings: dict[str, RBACBinding] = {}


@idam_v1_router.get("/rbac/bindings")
async def list_rbac_bindings(
    subject_type: str | None = None,
    subject_id: str | None = None,
    project: str | None = None,
) -> list[dict]:
    """List RBAC bindings with optional ``subject_type``/``subject_id``/``project`` filter.

    PS-71 §IW4.7 + idam-canonical-model-map §HTTP Contract: non-admin sees only
    bindings that apply to them (subject = self or in their groups); the
    host-app guard enforces this. This in-memory reference handler returns the
    raw set — host apps wrap with the resource-aware guard.
    """
    result = [
        asdict(b)
        for b in _bindings.values()
        if (subject_type is None or b.subject_type == subject_type)
        and (subject_id is None or b.subject_id == subject_id)
        and (project is None or b.project == project)
    ]
    return result


@idam_v1_router.post("/rbac/bindings", status_code=201)
async def create_rbac_binding(payload: dict) -> dict:
    """Create a new RBAC binding (gated ``idam.rbac.write`` by host-app guard)."""
    binding = RBACBinding(
        subject_type=str(payload.get("subject_type", "user")),   # type: ignore[arg-type]
        subject_id=str(payload.get("subject_id", "")),
        project=str(payload.get("project", "platform")),
        resource_type=str(payload.get("resource_type", "system")),
        resource_id=str(payload.get("resource_id", "*")),
        permission=str(payload.get("permission", "read")),
        granted_by=str(payload.get("granted_by", "system")),
    )
    _bindings[binding.binding_id] = binding
    return asdict(binding)


@idam_v1_router.get("/rbac/bindings/{binding_id}")
async def get_rbac_binding(binding_id: str) -> dict:
    """Return a single binding by id."""
    binding = _bindings.get(binding_id)
    if binding is None:
        raise HTTPException(status_code=404, detail="Not found")
    return asdict(binding)


@idam_v1_router.delete("/rbac/bindings/{binding_id}")
async def delete_rbac_binding(binding_id: str) -> dict[str, bool]:
    """Delete (revoke) a binding by id.

    Removing a binding MUST invalidate the affected subject's scoped-grants
    cache. The host application achieves this by wrapping the call with
    ``RBACEngine._invalidate_user(subject_id)`` (when the subject is a user) or
    by invalidating every member of the group (when the subject is a group).
    See the AT1.N_BindingWriteAPI test for the full pattern.
    """
    before = binding_id in _bindings
    _bindings.pop(binding_id, None)
    return {"ok": before}
