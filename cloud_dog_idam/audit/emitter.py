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

# cloud_dog_idam — Audit emitter
"""Append-only audit emitter with optional JSONL persistence."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cloud_dog_idam.audit.models import AuditEvent


class AuditEmitter:
    """Represent audit emitter."""
    def __init__(
        self,
        *,
        log_path: str | Path | None = None,
        also_log_to_memory: bool = False,
    ) -> None:
        self._log_path = Path(log_path).expanduser() if log_path else None
        self._also_log_to_memory = also_log_to_memory or self._log_path is None
        self._events: list[AuditEvent] = []
        if self._log_path is not None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _redact(details: dict[str, Any]) -> dict[str, Any]:
        clean = dict(details)
        for key, value in list(clean.items()):
            key_l = key.lower()
            if any(tok in key_l for tok in ("secret", "password", "token", "key")):
                clean[key] = "***REDACTED***"
            else:
                clean[key] = value
        return clean

    @staticmethod
    def _to_record(event: AuditEvent) -> dict[str, Any]:
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        return data

    def emit(self, event: AuditEvent) -> None:
        """Handle emit."""
        redacted = AuditEvent(
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            action=event.action,
            target=event.target,
            outcome=event.outcome,
            correlation_id=event.correlation_id,
            details=self._redact(event.details),
        )
        if self._also_log_to_memory:
            self._events.append(redacted)

        if self._log_path is None:
            return

        try:
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(self._to_record(redacted), sort_keys=True))
                handle.write("\n")
                handle.flush()
        except OSError as exc:
            print(
                f"AuditEmitter warning: unable to write audit event: {exc}",
                file=sys.stderr,
            )

    def list(self) -> list[AuditEvent]:
        """Handle list."""
        return list(self._events)
