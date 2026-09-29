"""Central EPSS bucketing used by both risk scoring and analysis stats."""

from typing import Literal

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD

EpssBucket = Literal["high", "medium", "low"]


def bucket_epss(epss_score: float) -> EpssBucket:
    """Classify an EPSS probability into high/medium/low (inclusive lower edges)."""
    if epss_score >= EPSS_HIGH_THRESHOLD:
        return "high"
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


# How alerts and cards name the high bucket, so a threshold change reaches the wording.
HIGH_EPSS_LABEL = f"EPSS >= {EPSS_HIGH_THRESHOLD:.0%}"
