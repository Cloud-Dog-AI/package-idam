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

"""Validate policy extension registration and evaluation semantics."""

from __future__ import annotations

import pytest

from cloud_dog_idam.domain.models import User
from cloud_dog_idam.rbac.policy_extensions import (
    authorise_with_extensions,
    clear_policy_evaluators,
    evaluate_policy_extensions,
    list_policy_evaluators,
    register_policy_evaluator,
)


@pytest.fixture(autouse=True)
def _clear_registry() -> None:
    clear_policy_evaluators()


def test_policy_extensions_all_must_allow() -> None:
    user = User(user_id="u1", username="u1")
    register_policy_evaluator("allow-one", lambda _u, _p, _c: True)
    register_policy_evaluator("allow-two", lambda _u, _p, _c: True)

    assert evaluate_policy_extensions(user, "users:read", {}) is True
    assert list_policy_evaluators() == ["allow-one", "allow-two"]


def test_policy_extensions_deny_on_false_or_exception() -> None:
    user = User(user_id="u1", username="u1")
    register_policy_evaluator("deny", lambda _u, _p, _c: False)
    assert evaluate_policy_extensions(user, "users:write", {}) is False

    clear_policy_evaluators()
    register_policy_evaluator("error", lambda _u, _p, _c: 1 / 0)
    assert evaluate_policy_extensions(user, "users:write", {}) is False


def test_authorise_with_extensions_composes_with_base_rbac_result() -> None:
    user = User(user_id="u1", username="u1")
    register_policy_evaluator("allow", lambda _u, _p, _c: True)

    assert authorise_with_extensions(True, user, "users:read", {}) is True
    assert authorise_with_extensions(False, user, "users:read", {}) is False


def test_duplicate_policy_name_rejected() -> None:
    register_policy_evaluator("x", lambda _u, _p, _c: True)
    with pytest.raises(ValueError):
        register_policy_evaluator("x", lambda _u, _p, _c: True)
