"""EPSS/KEV enrichment analyzer; the actual enrichment runs in analysis.py post-processing."""

from typing import Any, ClassVar

from .base import Analyzer


class EPSSKEVAnalyzer(Analyzer):
    """Post-processing analyzer enriching vulnerability findings with EPSS scores and CISA KEV data."""

    name = "epss_kev"

    is_post_processor = True

    depends_on: ClassVar[list[str]] = ["trivy", "grype", "osv", "deps_dev"]

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return a placeholder; enrichment happens in analysis.py post-processing."""
        return {
            "analyzer": self.name,
            "status": "deferred",
            "message": "EPSS/KEV enrichment runs as post-processing on vulnerability findings",
            "findings": [],
        }
