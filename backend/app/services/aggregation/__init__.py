"""Aggregation sub-package: ResultAggregator and stateless helpers."""

from app.services.aggregation.aggregator import ResultAggregator, is_error_result

__all__ = ["ResultAggregator", "is_error_result"]
