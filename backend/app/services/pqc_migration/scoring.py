"""
Priority scoring for PQC migration items. Returns 0..100 per asset.
Higher = migrate sooner. Status bucket thresholds: 80 / 50 / 25.
"""

import math
from datetime import datetime
from typing import Any, List

from app.services.pqc_migration.mappings_loader import Timeline


EXPOSURE_WEIGHT = 0.35
KEY_WEAKNESS_WEIGHT = 0.30
DEADLINE_WEIGHT = 0.25
COUNT_WEIGHT = 0.10

# --- Exposure calibration ---
# These map the "where is this asset deployed?" signal onto a 0..100 scale
# that feeds into the priority_score weighted sum. Higher number = more
# exposed = migrate sooner. Calibrated so that a public-facing X.509
# certificate (the worst case) saturates at 100 while a well-isolated
# binary embedding lands well below the default.
EXPOSURE_CERTIFICATE = 100.0       # public-facing X.509 / TLS material
EXPOSURE_RELATED_MATERIAL = 60.0   # certificate-adjacent material (e.g. CSR, chain)
EXPOSURE_SOURCE = 50.0             # crypto referenced from source code
EXPOSURE_DEFAULT = 45.0            # unclassified asset — assume moderate exposure
EXPOSURE_BINARY = 30.0             # crypto embedded in compiled binary (harder to reach)

# --- Count calibration ---
# A single instance of a vulnerable asset is already meaningful (one weak
# cert in production matters). We give it a non-zero baseline and scale
# logarithmically from there, capping at 100 for very large clusters.
_COUNT_BASELINE = 50.0
_COUNT_LOG_MULTIPLIER = 25.0

_MIN_KEY_SIZE = {
    "RSA": 2048,
    "DSA": 2048,
    "DH": 2048,
    "ECDSA": 256,
    "ECDH": 256,
}

_MIGRATION_BUCKETS = {
    "migrate_now": 80,
    "migrate_soon": 50,
    "plan_migration": 25,
    "monitor": 0,
}


def priority_score(
    *,
    asset: Any,
    source_family: str,
    timelines: List[Timeline],
    now: datetime,
    asset_count: int = 1,
) -> int:
    """Weighted sum of exposure, key-weakness, deadline, count components."""
    exposure = _score_exposure(asset)
    weakness = _score_key_weakness(asset, source_family)
    deadline = _score_deadline(source_family, timelines, now)
    count = _score_count(asset_count)
    raw = (
        exposure * EXPOSURE_WEIGHT + weakness * KEY_WEAKNESS_WEIGHT + deadline * DEADLINE_WEIGHT + count * COUNT_WEIGHT
    )
    return max(0, min(100, round(raw)))


def status_from_score(score: int) -> str:
    """Bucket a score 0..100 into a MigrationItemStatus value."""
    if score >= _MIGRATION_BUCKETS["migrate_now"]:
        return "migrate_now"
    if score >= _MIGRATION_BUCKETS["migrate_soon"]:
        return "migrate_soon"
    if score >= _MIGRATION_BUCKETS["plan_migration"]:
        return "plan_migration"
    return "monitor"


def _score_exposure(asset: Any) -> float:
    asset_type = _attr(asset, "asset_type") or ""
    cert_format = _attr(asset, "certificate_format") or ""
    detection_context = (_attr(asset, "detection_context") or "").lower()
    if asset_type == "certificate" and cert_format:
        return EXPOSURE_CERTIFICATE
    if asset_type == "related-crypto-material":
        return EXPOSURE_RELATED_MATERIAL
    if detection_context == "binary":
        return EXPOSURE_BINARY
    if detection_context == "source":
        return EXPOSURE_SOURCE
    return EXPOSURE_DEFAULT


def _score_key_weakness(asset: Any, source_family: str) -> float:
    key_size = _attr(asset, "key_size_bits")
    minimum = _MIN_KEY_SIZE.get(source_family)
    if key_size is None or minimum is None:
        return 50.0
    if key_size < minimum:
        return 100.0
    ratio = key_size / minimum
    if ratio >= 2.0:
        return 20.0
    if ratio >= 1.5:
        return 30.0
    if ratio >= 1.0:
        return 50.0
    return 100.0


def _score_deadline(source_family: str, timelines: List[Timeline], now: datetime) -> float:
    applicable = [t for t in timelines if source_family in t.applies_to]
    if not applicable:
        return 40.0
    nearest_days = min((t.deadline - now).days for t in applicable)
    if nearest_days < 0:
        return 100.0
    if nearest_days < 365:
        return 100.0
    if nearest_days < 365 * 3:
        return 70.0
    if nearest_days < 365 * 7:
        return 40.0
    return 20.0


def _score_count(count: int) -> float:
    """Translate an asset's occurrence count into a 0..100 contribution.

    Single-instance findings are not zeroed out — one production-exposed
    weak certificate is still a real risk. The score scales logarithmically
    from a baseline so clusters of 100+ identical assets cap at 100 instead
    of running away.
    """
    if count <= 0:
        return 0.0
    raw = _COUNT_BASELINE + math.log10(count) * _COUNT_LOG_MULTIPLIER
    return min(100.0, raw)


def _attr(obj: Any, name: str) -> Any:
    return getattr(obj, name, None) if not isinstance(obj, dict) else obj.get(name)
