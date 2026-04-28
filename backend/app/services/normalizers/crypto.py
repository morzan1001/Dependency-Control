"""Normalizer for crypto rule analyzer output.

The CryptoRuleAnalyzer already emits findings in the canonical
``Finding`` shape, so the normalizer just rehydrates each dict into a
``Finding`` and routes it through the aggregator the same way the
other analyzers do.
"""

from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding

if TYPE_CHECKING:
    from app.services.aggregation.aggregator import ResultAggregator


def normalize_crypto(
    aggregator: "ResultAggregator",
    result: Dict[str, Any],
    source: Optional[str] = None,
) -> None:
    for item in result.get("findings") or []:
        try:
            finding = Finding(**item)
        except Exception:
            continue
        aggregator.add_finding(finding, source=source)
