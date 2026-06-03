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

"""Validate JSONL persistence and dual-output mode for AuditEmitter."""

from __future__ import annotations

import json

from cloud_dog_idam.audit.emitter import AuditEmitter
from cloud_dog_idam.audit.models import AuditEvent


def test_audit_emitter_jsonl_persistence(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    emitter = AuditEmitter(log_path=path, also_log_to_memory=True)
    emitter.emit(
        AuditEvent(
            actor_id="user-1",
            action="login",
            target="auth/login",
            outcome="success",
            correlation_id="corr-1",
            details={"token": "raw-secret-token"},
        )
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    item = json.loads(lines[0])
    assert item["actor_id"] == "user-1"
    assert item["action"] == "login"
    assert item["target"] == "auth/login"
    assert item["outcome"] == "success"
    assert item["correlation_id"] == "corr-1"
    assert item["details"]["token"] == "***REDACTED***"
    assert emitter.list()[0].details["token"] == "***REDACTED***"
