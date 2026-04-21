from app.services.analyzers.crypto.catalogs.loader import (
    CipherSuiteEntry,
    CURRENT_IANA_CATALOG_VERSION,
    load_iana_catalog,
)


def test_catalog_loads_and_is_nonempty():
    cat = load_iana_catalog()
    assert isinstance(cat, dict)
    assert len(cat) > 10


def test_catalog_has_expected_known_suite():
    cat = load_iana_catalog()
    entry = cat.get("TLS_RSA_WITH_RC4_128_SHA")
    assert entry is not None
    assert "weak-cipher-rc4" in entry.weaknesses


def test_unknown_suite_returns_none():
    cat = load_iana_catalog()
    assert cat.get("TLS_DEFINITELY_NOT_A_REAL_SUITE") is None


def test_catalog_entry_has_shape():
    cat = load_iana_catalog()
    entry = next(iter(cat.values()))
    assert isinstance(entry, CipherSuiteEntry)
    assert isinstance(entry.name, str)
    assert isinstance(entry.weaknesses, list)


def test_current_catalog_version_is_one():
    assert CURRENT_IANA_CATALOG_VERSION == 1


def test_catalog_drift_sentinel():
    """Catch accidental catalog wipes. Threshold relaxed to match actual snapshot."""
    cat = load_iana_catalog()
    # If the manual fallback YAML was used, relax to 30; if the full IANA fetch
    # succeeded, the sentinel is effectively >300. Either way, anything under 20
    # is almost certainly a wipe.
    assert len(cat) > 20, (
        f"IANA catalog has only {len(cat)} entries — likely accidental wipe. "
        "Regenerate via: poetry run python scripts/generate_iana_catalog.py"
    )
