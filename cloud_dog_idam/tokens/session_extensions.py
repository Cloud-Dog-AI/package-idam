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

# cloud_dog_idam — session metadata extension hooks
"""Register and apply project-specific session metadata extension handlers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

_EXTENSION_KEY = "__extensions__"


@dataclass(frozen=True, slots=True)
class SessionExtension:
    """Represent session extension."""
    serializer: Callable[[Any], dict[str, Any]]
    deserializer: Callable[[dict[str, Any]], Any]


_registry: dict[str, SessionExtension] = {}


def register_session_extension(
    name: str,
    serializer: Callable[[Any], dict[str, Any]],
    deserializer: Callable[[dict[str, Any]], Any],
) -> None:
    """Register a named session extension serializer/deserializer pair."""

    clean = name.strip()
    if not clean:
        raise ValueError("Extension name must not be blank")
    if clean in _registry:
        raise ValueError(f"Session extension already registered: {clean}")
    _registry[clean] = SessionExtension(
        serializer=serializer, deserializer=deserializer
    )


def clear_session_extensions() -> None:
    """Clear registered extensions (primarily for deterministic tests)."""

    _registry.clear()


def list_session_extensions() -> list[str]:
    """List registered extension names."""

    return sorted(_registry.keys())


def apply_session_extensions(
    session_data: Mapping[str, Any], extension_values: Mapping[str, Any]
) -> dict[str, Any]:
    """Serialise extension values and merge into session payload."""

    payload = dict(session_data)
    serialised: dict[str, dict[str, Any]] = {}
    for name, value in extension_values.items():
        extension = _registry.get(name)
        if extension is None:
            raise KeyError(f"No extension registered for key: {name}")
        serialised[name] = extension.serializer(value)
    payload[_EXTENSION_KEY] = serialised
    return payload


def load_session_extensions(session_data: Mapping[str, Any]) -> dict[str, Any]:
    """Deserialise extension values from a session payload."""

    out: dict[str, Any] = {}
    stored = session_data.get(_EXTENSION_KEY, {})
    if not isinstance(stored, Mapping):
        return out
    for name, raw in stored.items():
        extension = _registry.get(str(name))
        if extension is None:
            continue
        if not isinstance(raw, Mapping):
            continue
        out[str(name)] = extension.deserializer(dict(raw))
    return out
