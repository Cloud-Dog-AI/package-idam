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

# cloud_dog_idam - Resource registry
"""Project resource registry consumed by the canonical RBAC WebUI."""

from __future__ import annotations

from dataclasses import asdict

from cloud_dog_idam.domain.models import ResourceRegistry, ResourceType


PLATFORM_RESOURCE_TYPES: tuple[ResourceType, ...] = (
    ResourceType(
        project="platform",
        resource_type="user_management",
        label="User Management",
        permissions=["read", "write", "admin"],
        list_endpoint="/idam/v1/users",
    ),
    ResourceType(
        project="platform",
        resource_type="system",
        label="System",
        permissions=["read", "write", "admin"],
        list_endpoint="/idam/v1/resource-registry",
    ),
)


class ResourceRegistryService:
    """Maintain project resource-type registrations for RBAC bindings."""

    def __init__(self, *, project: str = "platform") -> None:
        self._project = project
        self._resource_types: dict[tuple[str, str], ResourceType] = {
            (item.project, item.resource_type): item for item in PLATFORM_RESOURCE_TYPES
        }

    def register_resource_type(
        self,
        *,
        resource_type: str,
        label: str,
        permissions: list[str] | None = None,
        list_endpoint: str | None = None,
        project: str | None = None,
    ) -> ResourceType:
        """Register or replace one resource type."""
        resolved_project = project or self._project
        item = ResourceType(
            project=resolved_project,
            resource_type=resource_type,
            label=label,
            permissions=permissions or ["read", "write", "admin"],
            list_endpoint=list_endpoint,
        )
        self._resource_types[(resolved_project, resource_type)] = item
        return item

    def load_manifest(self, manifest: dict) -> ResourceRegistry:
        """Register resource types from a PS-70 project-extension manifest."""
        project = str(manifest.get("project") or self._project)
        resource_types = manifest.get("resource_types") or []
        for item in resource_types:
            if isinstance(item, str):
                self.register_resource_type(
                    project=project,
                    resource_type=item,
                    label=item.replace("_", " ").title(),
                )
                continue
            if isinstance(item, dict):
                self.register_resource_type(
                    project=project,
                    resource_type=str(item.get("type") or item.get("resource_type")),
                    label=str(item.get("label") or item.get("type") or ""),
                    permissions=[str(p) for p in item.get("permissions", [])]
                    or ["read", "write", "admin"],
                    list_endpoint=item.get("list_endpoint"),
                )
        return self.export(project=project)

    def export(self, *, project: str | None = None) -> ResourceRegistry:
        """Return platform defaults plus project-specific resource types."""
        selected_project = project or self._project
        resource_types = [
            item
            for item in self._resource_types.values()
            if item.project in {"platform", selected_project}
        ]
        resource_types.sort(key=lambda item: (item.project, item.resource_type))
        return ResourceRegistry(project=selected_project, resource_types=resource_types)

    def to_response(self, *, project: str | None = None) -> dict:
        """Return the PS-71 JSON response shape."""
        registry = self.export(project=project)
        return {
            "project": registry.project,
            "resource_types": [
                {
                    "type": item.resource_type,
                    "label": item.label,
                    "permissions": list(item.permissions),
                    "list_endpoint": item.list_endpoint,
                    "project": item.project,
                }
                for item in registry.resource_types
            ],
        }

    def asdict(self, *, project: str | None = None) -> dict:
        """Return a dataclass-shaped representation for tests and callers."""
        return asdict(self.export(project=project))
