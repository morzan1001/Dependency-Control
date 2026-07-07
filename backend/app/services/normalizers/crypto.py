"""Rehydrate pre-shaped crypto analyzer dicts into Finding objects."""

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding

if TYPE_CHECKING:
    from app.services.aggregation.aggregator import ResultAggregator

logger = logging.getLogger(__name__)


def normalize_crypto(
    aggregator: "ResultAggregator",
    result: Dict[str, Any],
    source: Optional[str] = None,
) -> None:
    for item in result.get("findings") or []:
        try:
            finding = Finding(**item)
        except Exception as exc:
            # Log rather than drop silently so analyzer output drift stays visible.
            logger.warning(
                "normalize_crypto: dropping unparseable finding (%s) — id=%s, type=%s",
                exc,
                item.get("id") if isinstance(item, dict) else None,
                item.get("type") if isinstance(item, dict) else None,
            )
            continue
        aggregator.add_finding(finding, source=source)
