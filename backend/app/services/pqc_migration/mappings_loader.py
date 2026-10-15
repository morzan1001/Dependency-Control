from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import yaml

from app.core import ensure_utc
from app.models.crypto_asset import CryptoAsset

CURRENT_MAPPINGS_VERSION = 1

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
    name: str
    deadline: datetime
    applies_to: list[str]


@dataclass(frozen=True)
class PQCMappings:
    mappings: list[PQCMapping]
    timelines: list[Timeline]
    # Upper-cased family or alias -> canonical source_family; CBOM tools emit names in arbitrary casing.
    families: dict[str, str]


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
            name=t["name"],
            deadline=ensure_utc(datetime.fromisoformat(t["deadline"])),
            applies_to=list(t.get("applies_to", [])),
        )
        for t in (doc.get("timelines") or [])
    ]
    families = {m.source_family.upper(): m.source_family for m in mappings}
    families.update({alias.upper(): family for alias, family in (doc.get("family_aliases") or {}).items()})
    return PQCMappings(mappings=mappings, timelines=timelines, families=families)


def normalise_family(name: str | None, mappings: PQCMappings) -> str:
    if not name:
        return ""
    return mappings.families.get(name.upper(), name)


def resolve_family(asset: CryptoAsset, mappings: PQCMappings) -> str:
    canonical = {m.source_family for m in mappings.mappings}
    for candidate in (asset.name, asset.variant):
        if (family := normalise_family(candidate, mappings)) in canonical:
            return family
    return ""
