from app.services.pqc_migration.mappings_loader import (
    CURRENT_MAPPINGS_VERSION,
    clear_mappings_cache,
    load_mappings,
    normalise_family,
)


def test_load_returns_populated_object():
    m = load_mappings()
    assert m.version == CURRENT_MAPPINGS_VERSION
    assert m.snapshot_date
    assert len(m.mappings) >= 5


def test_load_mappings_include_rsa_to_ml_kem():
    m = load_mappings()
    rsa = next(x for x in m.mappings if x.source_family == "RSA" and x.use_case == "key-exchange")
    assert rsa.recommended_pqc == "ML-KEM-768"


def test_load_timelines_present():
    m = load_mappings()
    assert len(m.timelines) >= 1
    first = m.timelines[0]
    assert first.deadline is not None


def test_family_alias_normalises():
    m = load_mappings()
    assert normalise_family("Diffie-Hellman", m) == "DH"
    assert normalise_family("ecDSA", m) == "ECDSA"
    assert normalise_family("RSA", m) == "RSA"
    assert normalise_family("Kyber", m) == "Kyber"


def test_family_alias_normalises_case_insensitively():
    """CBOM tools emit inconsistent casing for the same family. Alias
    resolution must be case-insensitive like the canonical fallback, or a
    quantum-vulnerable asset (e.g. ``diffie-hellman``) silently misses the
    alias, misses the canonical set (DH != DIFFIE-HELLMAN), and is dropped
    from the migration plan by ``generator._filter_vulnerable``."""
    m = load_mappings()
    assert normalise_family("diffie-hellman", m) == "DH"
    assert normalise_family("DIFFIE-HELLMAN", m) == "DH"
    assert normalise_family("EC-dsa", m) == "ECDSA"
    assert normalise_family("ECDSA", m) == "ECDSA"


def test_clear_mappings_cache_forces_reload():
    """``load_mappings`` is ``@lru_cache(maxsize=1)``. Without an explicit
    cache-clear, tests that patch the YAML or _MAPPINGS_PATH would keep
    seeing the first-process result. ``clear_mappings_cache`` exposes the
    underlying ``cache_clear`` so test setup can invalidate stale results."""
    # Prime the cache.
    first = load_mappings()
    assert load_mappings.cache_info().currsize == 1
    # Clear — next call repopulates.
    clear_mappings_cache()
    assert load_mappings.cache_info().currsize == 0
    second = load_mappings()
    # Same content (YAML unchanged), fresh object with full population.
    assert second.version == first.version
    assert load_mappings.cache_info().currsize == 1
