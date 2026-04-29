"""Aggregation sub-package: ResultAggregator and pure helpers.

The class itself lives in :mod:`app.services.aggregation.aggregator`. Pure
stateless helpers are split across:
  * :mod:`app.services.aggregation.versions`    - version parsing/normalization
  * :mod:`app.services.aggregation.components`  - component-name helpers
  * :mod:`app.services.aggregation.cross_link`  - finding cross-linking
"""

from app.services.aggregation.aggregator import ResultAggregator

__all__ = ["ResultAggregator"]
