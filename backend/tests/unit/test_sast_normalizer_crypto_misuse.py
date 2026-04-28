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


def test_crypto_misuse_rule_mapped_when_check_id_has_dotted_path_prefix():
    """Semgrep/OpenGrep emit `check_id` with a dotted path prefix when rules
    are loaded from a filesystem path (e.g. `/.semgrep/...`). The crypto-
    misuse rule name still lives in the last dot-separated segment, so a
    naive `startswith` against the whole string misses it. This test locks
    in that a nested-path check_id still maps to CRYPTO_KEY_MANAGEMENT."""
    # Nested-path check_id — the actual rule name is the final segment.
    nested = "rules.crypto-misuse.ecb-mode.crypto-misuse-ecb-mode-python"
    assert _finding_type_from_rule(nested) == FindingType.CRYPTO_KEY_MANAGEMENT

    # Variants that might occur depending on the Semgrep runner.
    assert (
        _finding_type_from_rule(".semgrep.rules.crypto-misuse-hardcoded-keys-python")
        == FindingType.CRYPTO_KEY_MANAGEMENT
    )
    assert (
        _finding_type_from_rule("my-org.crypto-misuse-weak-rng-java")
        == FindingType.CRYPTO_KEY_MANAGEMENT
    )

    # Regression: the bare rule-name form still works.
    assert (
        _finding_type_from_rule("crypto-misuse-ecb-mode-go")
        == FindingType.CRYPTO_KEY_MANAGEMENT
    )


def test_dotted_path_without_crypto_misuse_segment_is_plain_sast():
    """A dotted check_id whose FINAL segment is not a crypto-misuse rule
    must not be upgraded by the path-aware branch."""
    assert _finding_type_from_rule("rules.java.spring.csrf") == FindingType.SAST
    assert _finding_type_from_rule("python.lang.bad-import") == FindingType.SAST
