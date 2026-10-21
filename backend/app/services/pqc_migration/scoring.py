import math
from collections.abc import Sequence
from datetime import datetime

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_asset import CryptoAssetType
from app.schemas.pqc_migration import MigrationItemStatus

EXPOSURE_WEIGHT = 0.35
KEY_WEAKNESS_WEIGHT = 0.30
DEADLINE_WEIGHT = 0.25
COUNT_WEIGHT = 0.10

EXPOSURE_CERTIFICATE = 100.0
EXPOSURE_RELATED_MATERIAL = 60.0
EXPOSURE_SOURCE = 50.0
EXPOSURE_DEFAULT = 45.0  # unclassified asset — assume moderate exposure
EXPOSURE_BINARY = 30.0

_COUNT_BASELINE = 50.0
_COUNT_LOG_MULTIPLIER = 25.0

_MIN_KEY_SIZE = {
    "RSA": 2048,
    "DSA": 2048,
    "DH": 2048,
    "ECDSA": 256,
    "EdDSA": 256,
    "ECDH": 256,
}

# Lowest score of each status, highest first; priority_score clamps to 0..100, so one always matches.
_MIGRATION_BUCKETS: tuple[tuple[int, MigrationItemStatus], ...] = (
    (80, MigrationItemStatus.MIGRATE_NOW),
    (50, MigrationItemStatus.MIGRATE_SOON),
    (25, MigrationItemStatus.PLAN_MIGRATION),
    (0, MigrationItemStatus.MONITOR),
)


def priority_score(
    *,
    asset: CryptoAsset,
    source_family: str,
    deadline: datetime | None,
    now: datetime,
    asset_count: int = 1,
    referenced: float | None = None,
) -> int:
    raw = (
        _score_exposure(asset, referenced) * EXPOSURE_WEIGHT
        + _score_key_weakness(asset, source_family) * KEY_WEAKNESS_WEIGHT
        + _score_deadline(deadline, now) * DEADLINE_WEIGHT
        + _score_count(asset_count) * COUNT_WEIGHT
    )
    return max(0, min(100, round(raw)))


def status_from_score(score: int) -> MigrationItemStatus:
    return next(status for threshold, status in _MIGRATION_BUCKETS if score >= threshold)


def referenced_exposure(linked: Sequence[CryptoAsset]) -> dict[str, float]:
    """The exposure certificates and key material lend the algorithms they name, by bom_ref."""
    key_algorithms = {a.bom_ref: a.algorithm_ref for a in linked if a.algorithm_ref}
    exposure: dict[str, float] = {}

    def lend(ref: str | None, tier: float) -> None:
        if ref:
            exposure[ref] = max(exposure.get(ref, tier), tier)

    for a in linked:
        if a.asset_type == CryptoAssetType.RELATED_CRYPTO_MATERIAL:
            lend(a.algorithm_ref, EXPOSURE_RELATED_MATERIAL)
        elif a.asset_type == CryptoAssetType.CERTIFICATE and a.certificate_format:
            # A certificate usually names its key, and only the key names the algorithm.
            for ref in filter(None, (a.signature_algorithm_ref, a.subject_public_key_ref)):
                lend(ref, EXPOSURE_CERTIFICATE)
                lend(key_algorithms.get(ref), EXPOSURE_CERTIFICATE)
    return exposure


def _score_exposure(asset: CryptoAsset, referenced: float | None) -> float:
    if referenced is not None:
        return referenced
    detection_context = (asset.detection_context or "").lower()
    if detection_context == "binary":
        return EXPOSURE_BINARY
    if detection_context == "source":
        return EXPOSURE_SOURCE
    return EXPOSURE_DEFAULT


def _score_key_weakness(asset: CryptoAsset, source_family: str) -> float:
    key_size = asset.key_size_bits
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
    return 50.0


def _score_deadline(deadline: datetime | None, now: datetime) -> float:
    if deadline is None:
        return 40.0
    nearest_days = (deadline - now).days
    if nearest_days < 365:
        return 100.0
    if nearest_days < 365 * 3:
        return 70.0
    if nearest_days < 365 * 7:
        return 40.0
    return 20.0


def _score_count(count: int) -> float:
    if count <= 0:
        return 0.0
    raw = _COUNT_BASELINE + math.log10(count) * _COUNT_LOG_MULTIPLIER
    return min(100.0, raw)
