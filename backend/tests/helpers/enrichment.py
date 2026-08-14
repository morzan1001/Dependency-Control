"""Shared accessor for aggregator enrichment entries in tests."""


def enrichment_payload(aggregator, name: str, version: str) -> dict:
    for entry in aggregator.get_dependency_enrichments():
        if entry["name"] == name and entry["version"] == version:
            return entry["data"]
    raise AssertionError(f"no enrichment entry for {name}@{version}")
