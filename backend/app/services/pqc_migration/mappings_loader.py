from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import yaml

from app.core import ensure_utc
from app.models.crypto_asset import CryptoAsset

_MAPPINGS_PATH = Path(__file__).resolve().parent / "mappings.yaml"


@dataclass(frozen=True)
class PQCMapping:
    source_family: str
    source_primitive: str
    use_case: str
    recommended_pqc: str
    standard: str
    notes: str


@dataclass(frozen=True)
class Timeline:
    deadline: datetime
    applies_to: list[str]


@dataclass(frozen=True)
class PQCMappings:
    version: int
    mappings: list[PQCMapping]
    timelines: list[Timeline]
    # Upper-cased family or alias -> canonical source_family; CBOM tools emit names in arbitrary casing.
    families: dict[str, str]
    canonical: frozenset[str]


@lru_cache(maxsize=1)
def load_mappings() -> PQCMappings:
    with _MAPPINGS_PATH.open() as f:
        doc = yaml.safe_load(f) or {}
    mappings = [
        PQCMapping(
            source_family=m["source_family"],
            source_primitive=m["source_primitive"],
            use_case=m["use_case"],
            recommended_pqc=m["recommended_pqc"],
            standard=m["standard"],
            notes=(m.get("notes") or "").strip(),
        )
        for m in (doc.get("mappings") or [])
    ]
    timelines = [
        Timeline(
            deadline=ensure_utc(datetime.fromisoformat(t["deadline"])),
            applies_to=list(t.get("applies_to", [])),
        )
        for t in (doc.get("timelines") or [])
    ]
    families = {m.source_family.upper(): m.source_family for m in mappings}
    families.update({alias.upper(): family for alias, family in (doc.get("family_aliases") or {}).items()})
    return PQCMappings(
        version=doc["version"],
        mappings=mappings,
        timelines=timelines,
        families=families,
        canonical=frozenset(m.source_family for m in mappings),
    )


def normalise_family(name: str | None, mappings: PQCMappings) -> str:
    if not name:
        return ""
    return mappings.families.get(name.upper(), name)


def resolve_family(asset: CryptoAsset, mappings: PQCMappings) -> str:
    for candidate in (asset.name, asset.variant):
        if (family := normalise_family(candidate, mappings)) in mappings.canonical:
            return family
    return ""
