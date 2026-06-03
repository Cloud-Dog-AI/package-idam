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

"""Validate legacy API key record migration and dry-run behaviour."""

from __future__ import annotations

from cloud_dog_idam.api_keys.hashing import hash_api_key
from cloud_dog_idam.migration.api_keys import migrate_api_keys


def test_api_key_migration_dry_run_reports_without_mutating() -> None:
    records = [
        {"record_id": "r1", "raw_key": "alpha", "key_hash": "legacy"},
        {"record_id": "r2", "raw_key": "beta", "key_hash": "legacy"},
    ]

    result = migrate_api_keys(records, hash_algorithm="sha256", dry_run=True)

    assert result.total == 2
    assert result.migrated == 2
    assert result.skipped == 0
    assert result.failed == 0
    assert records[0]["key_hash"] == "legacy"


def test_api_key_migration_updates_hash_and_algorithm() -> None:
    records = [{"api_key_id": "key-1", "raw_key": "gamma", "key_hash": "old"}]

    result = migrate_api_keys(records, hash_algorithm="sha256", dry_run=False)

    assert result.migrated == 1
    assert result.failed == 0
    assert records[0]["key_hash"] == hash_api_key("gamma")
    assert records[0]["hash_algorithm"] == "sha256"


def test_api_key_migration_handles_missing_raw_key_and_progress_callback() -> None:
    records = [{"api_key_id": "key-1", "key_hash": "old"}]
    seen: list[tuple[int, int]] = []

    result = migrate_api_keys(
        records,
        hash_algorithm="sha256",
        progress_callback=lambda index, total: seen.append((index, total)),
    )

    assert seen == [(1, 1)]
    assert result.total == 1
    assert result.migrated == 0
    assert result.failed == 1
    assert result.failures[0].record_id == "key-1"
