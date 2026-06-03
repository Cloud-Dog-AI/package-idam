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

# cloud_dog_idam — Permission checker
"""Permission evaluation helpers for request-level authorisation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PermissionChecker:
    """Represent permission checker."""
    permissions: set[str]
    user_id: str
    owned_groups: set[str]

    def has_permission(self, permission: str) -> bool:
        """Return whether this has permission."""
        return permission in self.permissions or "*" in self.permissions

    def can_manage_group(self, group_id: str) -> bool:
        """Handle can manage group."""
        return self.has_permission("groups:manage") or group_id in self.owned_groups

    def can_access_resource(self, resource_owner_id: str) -> bool:
        """Handle can access resource."""
        return (
            self.has_permission("resources:read_any")
            or resource_owner_id == self.user_id
        )
