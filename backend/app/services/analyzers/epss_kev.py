"""EPSS/KEV enrichment analyzer; the actual enrichment runs in analysis.py post-processing."""

from typing import Any, Dict, List, Optional

from .base import Analyzer


class EPSSKEVAnalyzer(Analyzer):
    """Post-processing analyzer enriching vulnerability findings with EPSS scores and CISA KEV data."""

    name = "epss_kev"

    is_post_processor = True

    depends_on = ["trivy", "grype", "osv", "deps_dev"]

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Return a placeholder; enrichment happens in analysis.py post-processing."""
        return {
            "analyzer": self.name,
            "status": "deferred",
            "message": "EPSS/KEV enrichment runs as post-processing on vulnerability findings",
            "findings": [],
        }
