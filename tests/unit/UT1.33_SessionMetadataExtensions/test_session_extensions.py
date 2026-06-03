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

"""Validate session extension registration and payload serialisation."""

from __future__ import annotations

import pytest

from cloud_dog_idam.tokens.session_extensions import (
    apply_session_extensions,
    clear_session_extensions,
    list_session_extensions,
    load_session_extensions,
    register_session_extension,
)


@pytest.fixture(autouse=True)
def _clear_registry() -> None:
    clear_session_extensions()


def test_register_and_round_trip_session_extension() -> None:
    register_session_extension(
        "sharing",
        serializer=lambda payload: {"channel": payload["channel"]},
        deserializer=lambda payload: {"channel": payload["channel"]},
    )

    enriched = apply_session_extensions(
        {"base": "value"},
        {"sharing": {"channel": "team-alpha"}},
    )
    out = load_session_extensions(enriched)

    assert list_session_extensions() == ["sharing"]
    assert out["sharing"]["channel"] == "team-alpha"


def test_duplicate_extension_registration_is_rejected() -> None:
    register_session_extension(
        "k", serializer=lambda value: {}, deserializer=lambda data: data
    )
    with pytest.raises(ValueError):
        register_session_extension(
            "k", serializer=lambda value: {}, deserializer=lambda data: data
        )


def test_apply_extensions_requires_registered_name() -> None:
    with pytest.raises(KeyError):
        apply_session_extensions({}, {"unknown": {"x": 1}})
