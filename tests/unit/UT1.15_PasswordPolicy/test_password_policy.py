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

from cloud_dog_idam.config.models import PasswordPolicyConfig
from cloud_dog_idam.security.password_policy import PasswordPolicy


def test_password_policy_enforced() -> None:
    p = PasswordPolicy(PasswordPolicyConfig())
    valid, _ = p.validate("Abcd1234!efg")
    assert valid is True
