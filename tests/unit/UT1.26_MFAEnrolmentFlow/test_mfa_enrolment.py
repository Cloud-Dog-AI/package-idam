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

from cloud_dog_idam.security.mfa import consume_backup_code, enrol_mfa, hash_backup_code


def test_mfa_enrolment_backup_code_recovery() -> None:
    setup = enrol_mfa("gary")
    assert setup.otpauth_uri.startswith("otpauth://")
    hashes = {hash_backup_code(c) for c in setup.backup_codes}
    assert consume_backup_code(hashes, setup.backup_codes[0]) is True
