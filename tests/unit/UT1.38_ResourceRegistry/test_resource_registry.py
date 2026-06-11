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

from cloud_dog_idam.rbac.resource_registry import ResourceRegistryService


def test_resource_registry_exports_ps71_shape() -> None:
    service = ResourceRegistryService(project="file-mcp")
    service.load_manifest(
        {
            "project": "file-mcp",
            "resource_types": [
                {
                    "type": "storage_profile",
                    "label": "Storage Profile",
                    "permissions": ["read", "write", "admin"],
                    "list_endpoint": "/api/v1/storage-profiles",
                }
            ],
        }
    )

    response = service.to_response(project="file-mcp")

    assert response["project"] == "file-mcp"
    assert {
        "type": "storage_profile",
        "label": "Storage Profile",
        "permissions": ["read", "write", "admin"],
        "list_endpoint": "/api/v1/storage-profiles",
        "project": "file-mcp",
    } in response["resource_types"]
    assert any(item["type"] == "user_management" for item in response["resource_types"])
