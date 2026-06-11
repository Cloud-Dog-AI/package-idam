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

# cloud_dog_idam — Identity linking rules
"""Deterministic account-linking and conflict-resolution policies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cloud_dog_idam.audit.models import AuditEvent
from cloud_dog_idam.domain.models import IdentityLink


class LinkResolution(str, Enum):
    """Represent link resolution."""
    AUTO_LINK = "auto_link"
    ADMIN_APPROVAL = "admin_approval"
    REJECT = "reject"


@dataclass(slots=True)
class LinkDecision:
    """Represent link decision."""
    resolution: LinkResolution
    reason: str


class IdentityLinkingPolicy:
    """Linking policy engine for email/subject/admin-approval strategies."""

    def can_auto_link(
        self, *, strategy: str, email_match: bool, subject_match: bool
    ) -> bool:
        """Handle can auto link."""
        if strategy == "email":
            return email_match
        if strategy == "subject":
            return subject_match
        return False

    def resolve_link_conflict(
        self,
        *,
        strategy: str,
        existing_links: list[IdentityLink],
        incoming_provider: str,
        incoming_subject: str,
        email_match: bool,
        subject_match: bool,
    ) -> LinkDecision:
        """Resolve link conflict."""
        if any(
            link.provider_id == incoming_provider and link.subject == incoming_subject
            for link in existing_links
        ):
            return LinkDecision(
                LinkResolution.AUTO_LINK, "Exact provider-subject match"
            )

        if strategy == "admin_approval":
            return LinkDecision(
                LinkResolution.ADMIN_APPROVAL, "Policy requires explicit admin approval"
            )

        if self.can_auto_link(
            strategy=strategy, email_match=email_match, subject_match=subject_match
        ):
            return LinkDecision(LinkResolution.AUTO_LINK, "Auto-link policy matched")

        if existing_links:
            return LinkDecision(
                LinkResolution.ADMIN_APPROVAL,
                "Existing link conflict requires approval",
            )
        return LinkDecision(LinkResolution.REJECT, "No linking strategy matched")

    def create_audit_event(
        self,
        *,
        actor_id: str,
        action: str,
        target_identity_id: str,
        outcome: str,
        correlation_id: str,
        details: dict | None = None,
    ) -> AuditEvent:
        """Create audit event."""
        return AuditEvent(
            actor_id=actor_id,
            action=action,
            target=target_identity_id,
            outcome=outcome,
            correlation_id=correlation_id,
            details=details or {},
        )


def can_auto_link(*, strategy: str, email_match: bool, subject_match: bool) -> bool:
    """Handle can auto link."""
    return IdentityLinkingPolicy().can_auto_link(
        strategy=strategy,
        email_match=email_match,
        subject_match=subject_match,
    )
