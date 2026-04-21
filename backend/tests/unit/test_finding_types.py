from app.models.finding import FindingType


def test_crypto_finding_types_exist():
    assert FindingType.CRYPTO_WEAK_ALGORITHM.value == "crypto_weak_algorithm"
    assert FindingType.CRYPTO_WEAK_KEY.value == "crypto_weak_key"
    assert FindingType.CRYPTO_QUANTUM_VULNERABLE.value == "crypto_quantum_vulnerable"


def test_crypto_finding_types_distinct_from_existing():
    values = {ft.value for ft in FindingType}
    crypto_values = {
        "crypto_weak_algorithm",
        "crypto_weak_key",
        "crypto_quantum_vulnerable",
        "crypto_cert_expired",
        "crypto_cert_expiring_soon",
        "crypto_cert_not_yet_valid",
        "crypto_cert_weak_signature",
        "crypto_cert_weak_key",
        "crypto_cert_self_signed",
        "crypto_cert_validity_too_long",
        "crypto_weak_protocol",
    }
    assert crypto_values.issubset(values)
    # No collision with existing
    existing = values - crypto_values
    assert not any(v.startswith("crypto_") for v in existing)
