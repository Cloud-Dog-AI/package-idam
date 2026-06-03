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

# cloud_dog_idam — API key migration utilities
"""Batch migration helpers for legacy API key hash records."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cloud_dog_idam.api_keys.hashing import hash_api_key

try:
    from argon2 import PasswordHasher
except Exception:  # noqa: BLE001
    PasswordHasher = None  # type: ignore[assignment]


@dataclass(slots=True)
class MigrationFailure:
    """Represent migration failure."""
    record_id: str
    reason: str


@dataclass(slots=True)
class MigrationResult:
    """Represent migration result."""
    total: int
    migrated: int
    skipped: int
    failed: int
    failures: list[MigrationFailure] = field(default_factory=list)


def _record_identifier(record: MutableMapping[str, Any], index: int) -> str:
    return str(record.get("api_key_id") or record.get("record_id") or index)


def _resolve_raw_key(record: MutableMapping[str, Any]) -> str | None:
    for field_name in ("raw_key", "api_key", "plain_key", "key"):
        value = record.get(field_name)
        if isinstance(value, str) and value:
            return value
    return None


def _already_uses_algorithm(record: MutableMapping[str, Any], algorithm: str) -> bool:
    stored = str(record.get("key_hash", ""))
    if algorithm == "argon2":
        return stored.startswith("$argon2")
    if algorithm == "sha256":
        return len(stored) == 64 and all(
            c in "0123456789abcdef" for c in stored.lower()
        )
    return False


def _hash_key(raw_key: str, algorithm: str) -> str:
    if algorithm == "sha256":
        return hash_api_key(raw_key)
    if algorithm == "argon2":
        if PasswordHasher is None:
            raise RuntimeError("argon2-cffi is not installed")
        return PasswordHasher().hash(raw_key)
    raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def migrate_api_keys(
    source_records: Sequence[MutableMapping[str, Any]],
    hash_algorithm: str = "argon2",
    dry_run: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
) -> MigrationResult:
    """Re-hash legacy API key records into the requested hash format."""

    migrated = 0
    skipped = 0
    failures: list[MigrationFailure] = []
    total = len(source_records)

    for index, record in enumerate(source_records, start=1):
        if progress_callback is not None:
            progress_callback(index, total)

        record_id = _record_identifier(record, index)
        if _already_uses_algorithm(record, hash_algorithm):
            skipped += 1
            continue

        raw_key = _resolve_raw_key(record)
        if raw_key is None:
            failures.append(
                MigrationFailure(record_id=record_id, reason="Missing raw key material")
            )
            continue

        try:
            new_hash = _hash_key(raw_key, hash_algorithm)
        except Exception as exc:  # noqa: BLE001
            failures.append(MigrationFailure(record_id=record_id, reason=str(exc)))
            continue

        if not dry_run:
            record["key_hash"] = new_hash
            record["hash_algorithm"] = hash_algorithm
        migrated += 1

    return MigrationResult(
        total=total,
        migrated=migrated,
        skipped=skipped,
        failed=len(failures),
        failures=failures,
    )
