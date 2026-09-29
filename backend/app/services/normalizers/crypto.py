"""Rehydrate pre-shaped crypto analyzer dicts into Finding objects."""

from typing import TYPE_CHECKING, Any

from app.models.finding import Finding

if TYPE_CHECKING:
    from app.services.aggregation.aggregator import ResultAggregator


def normalize_crypto(
    aggregator: "ResultAggregator",
    result: dict[str, Any],
    source: str | None = None,
) -> None:
    for item in result.get("findings") or []:
        aggregator.add_finding(Finding(**item), source=source)
