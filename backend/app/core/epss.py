"""Central EPSS bucketing — single source of truth.

Both risk scoring and analysis stats classify EPSS scores into "high",
"medium", or "low" buckets. They previously used inconsistent boundary
semantics (one `>=`, the other `>`), which produced different bucket
assignments for scores landing exactly on a threshold. Anything that
needs to bucket an EPSS score should import from here.
"""

from typing import Literal

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD

EpssBucket = Literal["high", "medium", "low"]


def bucket_epss(epss_score: float) -> EpssBucket:
    """Classify an EPSS probability into high/medium/low.

    Boundaries are inclusive on the lower edge (`>=`), matching the
    docstrings on EPSS_HIGH_THRESHOLD and EPSS_MEDIUM_THRESHOLD.
    """
    if epss_score >= EPSS_HIGH_THRESHOLD:
        return "high"
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"
