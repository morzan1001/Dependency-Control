from app.services.pqc_migration.mappings_loader import (
    CURRENT_MAPPINGS_VERSION,
    PQCMapping,
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


def test_entry_types():
    m = load_mappings()
    assert isinstance(m.mappings[0], PQCMapping)
