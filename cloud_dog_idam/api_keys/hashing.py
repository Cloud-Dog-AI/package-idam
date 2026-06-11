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

# cloud_dog_idam — API key hashing
"""Hashing utilities for API key storage and comparison."""

from __future__ import annotations

import hashlib
import hmac


def hash_api_key(raw_key: str) -> str:
    """Handle hash api key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def key_matches(raw_key: str, stored_hash: str) -> bool:
    """Handle key matches."""
    return hmac.compare_digest(hash_api_key(raw_key), stored_hash)
