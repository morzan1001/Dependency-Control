"""Tests for CryptoRule expiry and weakness extensions (Phase 2)."""

import pytest
from pydantic import ValidationError

from app.models.finding import FindingType, Severity
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule


def _base_rule_kwargs(**overrides):
    base = dict(
        rule_id="r",
        name="r",
        description="",
        finding_type=FindingType.CRYPTO_CERT_EXPIRING_SOON,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
    )
    base.update(overrides)
    return base


def test_expiry_fields_default_to_none():
    r = CryptoRule(**_base_rule_kwargs())
    assert r.expiry_critical_days is None
    assert r.expiry_high_days is None
    assert r.expiry_medium_days is None
    assert r.expiry_low_days is None
    assert r.validity_too_long_days is None


def test_expiry_fields_accept_positive_int():
    r = CryptoRule(
        **_base_rule_kwargs(
            expiry_critical_days=7,
            expiry_high_days=30,
            expiry_medium_days=90,
            expiry_low_days=180,
            validity_too_long_days=398,
        )
    )
    assert r.expiry_critical_days == 7
    assert r.expiry_high_days == 30
    assert r.expiry_medium_days == 90
    assert r.expiry_low_days == 180
    assert r.validity_too_long_days == 398


def test_expiry_negative_values_rejected():
    with pytest.raises(ValidationError):
        CryptoRule(**_base_rule_kwargs(expiry_critical_days=-5))


def test_match_cipher_weaknesses_defaults_to_empty_list():
    r = CryptoRule(**_base_rule_kwargs())
    assert r.match_cipher_weaknesses == []


def test_match_cipher_weaknesses_accepts_tag_list():
    r = CryptoRule(
        **_base_rule_kwargs(
            finding_type=FindingType.CRYPTO_WEAK_PROTOCOL,
            match_cipher_weaknesses=["weak-cipher-rc4", "no-forward-secrecy"],
        )
    )
    assert "weak-cipher-rc4" in r.match_cipher_weaknesses
