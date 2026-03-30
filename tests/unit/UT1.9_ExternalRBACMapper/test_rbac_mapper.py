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

from cloud_dog_idam.rbac.mappers import map_external_groups, map_external_roles


def test_mappers() -> None:
    assert map_external_groups(["admins"], {"admins": "admin"}) == ["admin"]
    assert map_external_roles(["viewer"], {"viewer": "viewer"}) == ["viewer"]
