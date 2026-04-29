"""Deprecated: import from ``app.services.analyzers.license_compliance`` instead.

Kept as a thin re-export shim so existing
``from app.services.analyzers.license import LicenseAnalyzer`` imports
continue to resolve.
"""

from app.services.analyzers.license_compliance import LicenseAnalyzer  # noqa: F401

__all__ = ["LicenseAnalyzer"]
