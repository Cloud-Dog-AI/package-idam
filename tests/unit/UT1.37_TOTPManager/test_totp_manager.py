# Copyright 2026 Cloud-Dog, Viewdeck Engineering Limited
# Licensed under the Apache License, Version 2.0
"""UM10 TOTP/MFA manager tests.

Requirements: UM10
Tasks: W28A-696
"""

import pyotp

from cloud_dog_idam.domain.models import User
from cloud_dog_idam.users.service import UserService
from cloud_dog_idam.security.totp import TOTPManager


def _create_manager() -> tuple[TOTPManager, UserService, str]:
    user_svc = UserService()
    user = user_svc.create(User(username="mfa-test", email="mfa@test.com"))
    mgr = TOTPManager(user_svc)
    return mgr, user_svc, user.user_id


def test_generate_secret_and_verify_valid_code():
    """Generate TOTP secret, produce a valid code, verify it passes."""
    mgr, user_svc, uid = _create_manager()
    result = mgr.generate_secret(uid)

    assert result.secret
    assert result.otpauth_uri.startswith("otpauth://")
    assert len(result.backup_codes) == 10

    # Generate a real valid code from the secret.
    valid_code = pyotp.TOTP(result.secret).now()

    # Enable MFA with valid code.
    assert mgr.enable_mfa(uid, result.secret, valid_code) is True

    # Verify works after enabling.
    fresh_code = pyotp.TOTP(result.secret).now()
    assert mgr.verify_totp(uid, fresh_code) is True


def test_verify_rejects_invalid_code():
    """Invalid TOTP code is rejected."""
    mgr, user_svc, uid = _create_manager()
    result = mgr.generate_secret(uid)
    valid_code = pyotp.TOTP(result.secret).now()
    mgr.enable_mfa(uid, result.secret, valid_code)

    assert mgr.verify_totp(uid, "000000") is False


def test_enable_mfa_flow():
    """Full MFA enable lifecycle: setup -> verify -> enable."""
    mgr, user_svc, uid = _create_manager()

    # Step 1: Generate secret.
    setup = mgr.generate_secret(uid)

    # Step 2: Verify with wrong code fails.
    assert mgr.enable_mfa(uid, setup.secret, "999999") is False

    # Step 3: Verify with valid code succeeds.
    code = pyotp.TOTP(setup.secret).now()
    assert mgr.enable_mfa(uid, setup.secret, code) is True

    # Step 4: User now has MFA enabled.
    user = user_svc.get(uid)
    assert user.mfa_enabled is True
    assert user.totp_secret == setup.secret


def test_backup_codes_are_single_use():
    """Backup codes work once and are consumed."""
    mgr, user_svc, uid = _create_manager()
    setup = mgr.generate_secret(uid)
    code = pyotp.TOTP(setup.secret).now()
    mgr.enable_mfa(uid, setup.secret, code)

    # Generate fresh backup codes.
    backups = mgr.generate_backup_codes(uid, count=5)
    assert len(backups) == 5

    # First use succeeds.
    assert mgr.use_backup_code(uid, backups[0]) is True

    # Second use of same code fails (single-use).
    assert mgr.use_backup_code(uid, backups[0]) is False

    # Other codes still work.
    assert mgr.use_backup_code(uid, backups[1]) is True


def test_disable_mfa():
    """MFA can be disabled, clearing secret and backup codes."""
    mgr, user_svc, uid = _create_manager()
    setup = mgr.generate_secret(uid)
    code = pyotp.TOTP(setup.secret).now()
    mgr.enable_mfa(uid, setup.secret, code)

    assert mgr.disable_mfa(uid) is True
    user = user_svc.get(uid)
    assert user.mfa_enabled is False
    assert user.totp_secret is None
    assert user.backup_codes is None
