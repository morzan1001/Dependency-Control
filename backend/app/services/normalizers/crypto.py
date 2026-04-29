"""Normalizer for crypto rule analyzer output.

The CryptoRuleAnalyzer already emits findings in the canonical
``Finding`` shape, so the normalizer just rehydrates each dict into a
``Finding`` and routes it through the aggregator the same way the
other analyzers do.
"""

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
            # A malformed crypto finding shouldn't take down the whole scan,
            # but it must not vanish silently — analyzer output drift would
            # otherwise be invisible until users notice missing findings.
            logger.warning(
                "normalize_crypto: dropping unparseable finding (%s) — id=%s, type=%s",
                exc,
                item.get("id") if isinstance(item, dict) else None,
                item.get("type") if isinstance(item, dict) else None,
            )
            continue
        aggregator.add_finding(finding, source=source)
