"""Deprecated: import from :mod:`app.services.aggregation`.

This module is retained as a backward-compatibility shim so that existing
imports such as ``from app.services.aggregator import ResultAggregator``
continue to resolve. New code should depend on the sub-package directly.
"""

from app.services.aggregation import ResultAggregator  # noqa: F401

__all__ = ["ResultAggregator"]
