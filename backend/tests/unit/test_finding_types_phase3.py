from app.models.finding import FindingType


def test_crypto_key_management_exists():
    assert FindingType.CRYPTO_KEY_MANAGEMENT.value == "crypto_key_management"


def test_total_crypto_finding_types_count():
    values = {ft.value for ft in FindingType}
    crypto_values = {v for v in values if v.startswith("crypto_")}
    assert len(crypto_values) >= 12  # 3 Phase-1 + 8 Phase-2 + 1 Phase-3
    assert "crypto_key_management" in crypto_values
