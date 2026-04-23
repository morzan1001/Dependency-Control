from app.models.finding import FindingType
from app.services.normalizers.sast import _finding_type_from_rule


def test_crypto_misuse_rule_maps_to_crypto_key_management():
    assert _finding_type_from_rule("crypto-misuse-hardcoded-keys-python") == FindingType.CRYPTO_KEY_MANAGEMENT
    assert _finding_type_from_rule("crypto-misuse-weak-rng-java") == FindingType.CRYPTO_KEY_MANAGEMENT
    assert _finding_type_from_rule("crypto-misuse-ecb-mode-go") == FindingType.CRYPTO_KEY_MANAGEMENT


def test_regular_sast_rule_stays_as_sast():
    assert _finding_type_from_rule("python.lang.bad-import") == FindingType.SAST
    assert _finding_type_from_rule("java.spring.csrf") == FindingType.SAST


def test_none_or_empty_rule_defaults_to_sast():
    assert _finding_type_from_rule(None) == FindingType.SAST
    assert _finding_type_from_rule("") == FindingType.SAST


def test_prefix_boundary_is_strict():
    # Ensure substring matches don't false-positive
    assert _finding_type_from_rule("other-crypto-misuse-foo") == FindingType.SAST
