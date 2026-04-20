from app.models.finding import FindingType


def test_crypto_finding_types_exist():
    assert FindingType.CRYPTO_WEAK_ALGORITHM.value == "crypto_weak_algorithm"
    assert FindingType.CRYPTO_WEAK_KEY.value == "crypto_weak_key"
    assert FindingType.CRYPTO_QUANTUM_VULNERABLE.value == "crypto_quantum_vulnerable"


def test_crypto_finding_types_distinct_from_existing():
    values = {ft.value for ft in FindingType}
    crypto_values = {"crypto_weak_algorithm", "crypto_weak_key", "crypto_quantum_vulnerable"}
    assert crypto_values.issubset(values)
    # No collision with existing
    existing = values - crypto_values
    assert not any(v.startswith("crypto_") for v in existing)
