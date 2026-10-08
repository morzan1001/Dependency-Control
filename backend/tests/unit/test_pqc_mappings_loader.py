from pathlib import Path

import yaml

from app.services.pqc_migration import mappings_loader
from app.services.pqc_migration.mappings_loader import (
    CURRENT_MAPPINGS_VERSION,
    load_mappings,
    normalise_family,
)


def test_load_returns_populated_object():
    assert len(load_mappings().mappings) >= 5


def test_the_mappings_file_carries_the_version_plans_report():
    doc = yaml.safe_load(Path(mappings_loader.__file__).with_name("mappings.yaml").read_text())

    assert doc["version"] == CURRENT_MAPPINGS_VERSION


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
    """Alias resolution must be case-insensitive, or a quantum-vulnerable asset misses both the alias and the canonical set and is dropped from the migration plan."""
    m = load_mappings()
    assert normalise_family("diffie-hellman", m) == "DH"
    assert normalise_family("DIFFIE-HELLMAN", m) == "DH"
    assert normalise_family("EC-dsa", m) == "ECDSA"
    assert normalise_family("ECDSA", m) == "ECDSA"
