from pathlib import Path

import yaml

from app.services.pqc_migration.mappings_loader import load_mappings


def test_all_quantum_vulnerable_families_have_a_mapping():
    """Every family listed as quantum-vulnerable in the Phase-1 seed rule
    `pqc-quantum-vulnerable-pke` must have at least one entry in mappings.yaml."""
    seed_path = (
        Path(__file__).resolve().parents[2]
        / "app" / "services" / "crypto_policy" / "seed" / "nist_pqc.yaml"
    )
    with seed_path.open() as f:
        seed = yaml.safe_load(f)
    rule = next(r for r in seed["rules"] if r["rule_id"] == "pqc-quantum-vulnerable-pke")
    vulnerable_families = set(rule["match_name_patterns"])

    m = load_mappings()
    canonical_covered = {mp.source_family for mp in m.mappings}
    aliased_covered = set(m.family_aliases.keys())
    covered = canonical_covered | aliased_covered

    missing = vulnerable_families - covered
    assert not missing, (
        f"Families listed as quantum-vulnerable in Phase-1 seed are missing "
        f"from mappings.yaml: {sorted(missing)}. "
        f"Either add a PQCMapping entry or a family_aliases entry."
    )
