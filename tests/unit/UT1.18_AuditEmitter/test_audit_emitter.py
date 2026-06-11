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

from cloud_dog_idam.audit.emitter import AuditEmitter
from cloud_dog_idam.audit.models import AuditEvent


def test_audit_redaction() -> None:
    e = AuditEmitter()
    e.emit(AuditEvent(actor_id="u1", action="login", details={"token": "abc"}))
    assert e.list()[0].details["token"] == "***REDACTED***"


def test_audit_emitter_writes_jsonl(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"
    e = AuditEmitter(log_path=log_path, also_log_to_memory=True)
    e.emit(
        AuditEvent(
            actor_id="u2",
            action="create_user",
            target="users/u2",
            details={"password": "unsafe", "source": "unit-test"},
        )
    )
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert '"action": "create_user"' in lines[0]
    assert '"password": "***REDACTED***"' in lines[0]
