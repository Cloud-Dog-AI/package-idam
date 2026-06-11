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

# cloud_dog_idam — policy extension points
"""Custom permission evaluators that run after baseline RBAC checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from cloud_dog_idam.domain.models import User

PolicyEvaluator = Callable[[User, str, Mapping[str, Any]], bool]


_registry: dict[str, PolicyEvaluator] = {}


def register_policy_evaluator(
    name: str,
    evaluator_fn: PolicyEvaluator,
    *,
    replace: bool = False,
) -> None:
    """Register a custom policy evaluator by name."""

    clean = name.strip()
    if not clean:
        raise ValueError("Policy evaluator name must not be blank")
    if clean in _registry and not replace:
        raise ValueError(f"Policy evaluator already registered: {clean}")
    _registry[clean] = evaluator_fn


def deregister_policy_evaluator(name: str) -> bool:
    """Remove a policy evaluator by name."""

    return _registry.pop(name, None) is not None


def list_policy_evaluators() -> list[str]:
    """List registered evaluator names."""

    return sorted(_registry.keys())


def clear_policy_evaluators() -> None:
    """Clear all evaluators (primarily for deterministic tests)."""

    _registry.clear()


def evaluate_policy_extensions(
    user: User,
    permission: str,
    context: Mapping[str, Any] | None = None,
) -> bool:
    """Return True only if all policy evaluators allow access."""

    payload = context or {}
    for evaluator in _registry.values():
        try:
            if not evaluator(user, permission, payload):
                return False
        except Exception:  # noqa: BLE001
            return False
    return True


def authorise_with_extensions(
    base_allowed: bool,
    user: User,
    permission: str,
    context: Mapping[str, Any] | None = None,
) -> bool:
    """Compose baseline RBAC decision with extension evaluators."""

    if not base_allowed:
        return False
    return evaluate_policy_extensions(user, permission, context)
