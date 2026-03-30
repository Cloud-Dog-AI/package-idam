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

# cloud_dog_idam — Domain errors
"""Portable exception taxonomy for IDAM operations."""

from __future__ import annotations


class IDAMError(Exception):
    """Base exception for cloud_dog_idam."""


class AuthenticationError(IDAMError):
    """Authentication failed."""


class AuthorisationError(IDAMError):
    """Authorisation failed."""


class ValidationError(IDAMError):
    """Input validation failed."""


class TokenError(IDAMError):
    """Token issue/verification error."""
