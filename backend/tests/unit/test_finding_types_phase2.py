"""Tests for Phase 2 crypto finding types."""

from app.models.finding import FindingType


def test_cert_finding_types_exist():
    assert FindingType.CRYPTO_CERT_EXPIRED.value == "crypto_cert_expired"
    assert FindingType.CRYPTO_CERT_EXPIRING_SOON.value == "crypto_cert_expiring_soon"
    assert FindingType.CRYPTO_CERT_NOT_YET_VALID.value == "crypto_cert_not_yet_valid"
    assert FindingType.CRYPTO_CERT_WEAK_SIGNATURE.value == "crypto_cert_weak_signature"
    assert FindingType.CRYPTO_CERT_WEAK_KEY.value == "crypto_cert_weak_key"
    assert FindingType.CRYPTO_CERT_SELF_SIGNED.value == "crypto_cert_self_signed"
    assert FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG.value == "crypto_cert_validity_too_long"


def test_protocol_finding_type_exists():
    assert FindingType.CRYPTO_WEAK_PROTOCOL.value == "crypto_weak_protocol"


def test_all_eight_phase2_types_present():
    values = {ft.value for ft in FindingType}
    expected = {
        "crypto_cert_expired",
        "crypto_cert_expiring_soon",
        "crypto_cert_not_yet_valid",
        "crypto_cert_weak_signature",
        "crypto_cert_weak_key",
        "crypto_cert_self_signed",
        "crypto_cert_validity_too_long",
        "crypto_weak_protocol",
    }
    assert expected.issubset(values)
