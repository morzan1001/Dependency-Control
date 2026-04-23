"""
Loader for the PQC mappings YAML snapshot. Cached in-memory per-process.
Bump CURRENT_MAPPINGS_VERSION and regenerate snapshot_date when NIST
publishes new standards.
"""

from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

import yaml

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
    applies_to: List[str]


@dataclass(frozen=True)
class PQCMappings:
    version: int
    snapshot_date: str
    mappings: List[PQCMapping]
    timelines: List[Timeline]
    family_aliases: Dict[str, str]


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
            deadline=_parse_date(t["deadline"]),
            applies_to=list(t.get("applies_to", [])),
        )
        for t in (doc.get("timelines") or [])
    ]
    return PQCMappings(
        version=int(doc.get("version", 1)),
        snapshot_date=doc.get("snapshot_date", ""),
        mappings=mappings,
        timelines=timelines,
        family_aliases=dict(doc.get("family_aliases") or {}),
    )


def clear_mappings_cache() -> None:
    """Clear the in-process ``load_mappings`` cache.

    Test-only helper: because ``load_mappings`` uses ``@lru_cache(maxsize=1)``,
    patching the YAML file or swapping ``_MAPPINGS_PATH`` within a single
    process will not take effect until the cache is invalidated. Call this
    helper from test setup/teardown to force a re-read.
    """
    load_mappings.cache_clear()


def _parse_date(s: str) -> datetime:
    from datetime import timezone

    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def normalise_family(name: Optional[str], mappings: PQCMappings) -> str:
    """Resolve an asset name to its canonical source_family."""
    if not name:
        return ""
    if name in mappings.family_aliases:
        return mappings.family_aliases[name]
    canonical = {m.source_family for m in mappings.mappings}
    if name in canonical:
        return name
    upper = name.upper()
    for canon in canonical:
        if canon.upper() == upper:
            return canon
    return name
