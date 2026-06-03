# Copyright 2026 Cloud-Dog, Viewdeck Engineering Limited
# Licensed under the Apache License, Version 2.0
"""UM9 cascade delete tests.

Requirements: UM9
Tasks: W28A-696
"""

from cloud_dog_idam.domain.models import User
from cloud_dog_idam.users.service import UserService
from cloud_dog_idam.api_keys.manager import APIKeyManager
from cloud_dog_idam.tokens.sessions import SessionManager
from cloud_dog_idam.users.groups import GroupService
from cloud_dog_idam.audit.emitter import AuditEmitter
from cloud_dog_idam.domain.models import Group
from cloud_dog_idam.users.cascade import delete_user_cascade


def test_cascade_deletes_user_and_related_entities():
    """Create user with API keys, groups, sessions -> cascade delete -> verify all gone."""
    user_svc = UserService()
    key_mgr = APIKeyManager()
    session_mgr = SessionManager()
    group_svc = GroupService()
    audit = AuditEmitter(also_log_to_memory=True)

    user = user_svc.create(User(username="cascade-test", email="c@test.com", role="user"))
    uid = user.user_id

    # Create related entities.
    raw_key, _ = key_mgr.generate(uid)
    session = session_mgr.create(uid)
    group = group_svc.create(Group(name="test-group"))
    group_svc.add_member(group.group_id, uid)

    # Verify setup.
    assert key_mgr.list_keys(owner_id=uid)
    assert session_mgr.get(session.session_id) is not None
    assert uid in group_svc.members(group.group_id)

    # Cascade delete.
    result = delete_user_cascade(
        uid,
        user_service=user_svc,
        api_key_manager=key_mgr,
        session_manager=session_mgr,
        group_service=group_svc,
        audit_emitter=audit,
        actor_id="admin-test",
    )

    assert result.user_deleted is True
    assert result.api_keys_deleted >= 1
    assert result.sessions_deleted >= 1
    assert result.group_memberships_removed >= 1
    assert not result.errors
    assert user_svc.get(uid) is None


def test_cascade_delete_emits_audit_before_deletion():
    """Verify audit event is emitted BEFORE deletion starts."""
    user_svc = UserService()
    audit = AuditEmitter(also_log_to_memory=True)

    user = user_svc.create(User(username="audit-test", email="a@test.com"))

    result = delete_user_cascade(
        user.user_id,
        user_service=user_svc,
        audit_emitter=audit,
        actor_id="admin",
    )

    assert result.user_deleted is True
    events = audit.list()
    assert len(events) >= 2
    assert events[0].action == "user.cascade_delete"
    assert events[0].outcome == "initiated"
    assert events[1].action == "user.cascade_delete"
    assert events[1].outcome == "success"


def test_cascade_delete_returns_not_found_for_missing_user():
    """Non-existent user returns error, not exception."""
    user_svc = UserService()
    result = delete_user_cascade("nonexistent", user_service=user_svc)
    assert result.user_deleted is False
    assert "not found" in result.errors[0].lower()
