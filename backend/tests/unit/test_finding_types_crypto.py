"""Tests for crypto-related FindingType enum members (phase 1-3 consolidated)."""

import pytest

from app.models.finding import FindingType

CRYPTO_FINDING_TYPES = [
    # Phase 1 — algorithms/keys/quantum
    (FindingType.CRYPTO_WEAK_ALGORITHM, "crypto_weak_algorithm"),
    (FindingType.CRYPTO_WEAK_KEY, "crypto_weak_key"),
    (FindingType.CRYPTO_QUANTUM_VULNERABLE, "crypto_quantum_vulnerable"),
    # Phase 2 — certificates + protocols
    (FindingType.CRYPTO_CERT_EXPIRED, "crypto_cert_expired"),
    (FindingType.CRYPTO_CERT_EXPIRING_SOON, "crypto_cert_expiring_soon"),
    (FindingType.CRYPTO_CERT_NOT_YET_VALID, "crypto_cert_not_yet_valid"),
    (FindingType.CRYPTO_CERT_WEAK_SIGNATURE, "crypto_cert_weak_signature"),
    (FindingType.CRYPTO_CERT_WEAK_KEY, "crypto_cert_weak_key"),
    (FindingType.CRYPTO_CERT_SELF_SIGNED, "crypto_cert_self_signed"),
    (FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG, "crypto_cert_validity_too_long"),
    (FindingType.CRYPTO_WEAK_PROTOCOL, "crypto_weak_protocol"),
    # Phase 3 — key management
    (FindingType.CRYPTO_KEY_MANAGEMENT, "crypto_key_management"),
]


@pytest.mark.parametrize("member,expected_value", CRYPTO_FINDING_TYPES)
def test_crypto_finding_type_value(member, expected_value):
    assert member.value == expected_value


def test_no_existing_finding_type_collides_with_crypto_prefix():
    crypto_values = {value for _, value in CRYPTO_FINDING_TYPES}
    all_values = {ft.value for ft in FindingType}
    non_crypto_values = all_values - crypto_values
    assert not any(v.startswith("crypto_") for v in non_crypto_values)
