from typing import Literal

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD

EpssBucket = Literal["high", "medium", "low"]


def bucket_epss(epss_score: float) -> EpssBucket:
    if epss_score >= EPSS_HIGH_THRESHOLD:
        return "high"
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


# How alerts and cards name the high bucket, so a threshold change reaches the wording.
HIGH_EPSS_LABEL = f"EPSS >= {EPSS_HIGH_THRESHOLD:.0%}"
