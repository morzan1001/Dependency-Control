from pathlib import Path

import yaml

from app.services.pqc_migration.mappings_loader import load_mappings, normalise_family


def test_all_quantum_vulnerable_families_have_a_mapping():
    """Every quantum-vulnerable family in the seed rule must be covered by mappings.yaml."""
    seed_path = Path(__file__).resolve().parents[2] / "app" / "services" / "crypto_policy" / "seed" / "nist_pqc.yaml"
    with seed_path.open() as f:
        seed = yaml.safe_load(f)
    rule = next(r for r in seed["rules"] if r["rule_id"] == "pqc-quantum-vulnerable-pke")
    vulnerable_families = set(rule["match_name_patterns"])

    m = load_mappings()
    canonical = {mp.source_family for mp in m.mappings}

    missing = {family for family in vulnerable_families if normalise_family(family, m) not in canonical}
    assert not missing, (
        f"Families listed as quantum-vulnerable in Phase-1 seed are missing "
        f"from mappings.yaml: {sorted(missing)}. "
        f"Either add a PQCMapping entry or a family_aliases entry."
    )
