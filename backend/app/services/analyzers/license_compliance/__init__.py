"""License compliance analyzer package.

Public surface:
- :class:`LicenseAnalyzer` — orchestrates per-component evaluation.
- :data:`LICENSE_DATABASE` — recognised SPDX identifiers and metadata.

Sub-modules:
- :mod:`constants`     — string constants, regexes, severity ranks, license DB.
- :mod:`normalizer`    — pure SPDX normalization / expression parsing helpers.
- :mod:`compatibility` — cross-component license-pair conflict detection.
- :mod:`evaluator`     — per-license severity evaluation and finding factory.
- :mod:`analyzer`      — the :class:`LicenseAnalyzer` class itself.
"""

from .analyzer import LicenseAnalyzer
from .constants import LICENSE_DATABASE

__all__ = ["LicenseAnalyzer", "LICENSE_DATABASE"]
