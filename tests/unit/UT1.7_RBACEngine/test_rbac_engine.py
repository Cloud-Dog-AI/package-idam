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

from cloud_dog_idam.rbac.engine import RBACEngine


def test_rbac_union_permissions() -> None:
    e = RBACEngine()
    e.assign_role_to_user("u1", "viewer")
    e.assign_role_to_group("g1", "user")
    e.add_user_to_group("u1", "g1")
    perms = e.get_effective_permissions("u1")
    assert "resources:read" in perms
    assert "resources:write" in perms
