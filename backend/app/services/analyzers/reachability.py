"""Reachability analyzer; the actual enrichment runs in analysis.py post-processing."""

from typing import Any, Dict, List, Optional

from .base import Analyzer


class ReachabilityAnalyzer(Analyzer):
    """Post-processing analyzer enriching vulnerability findings with reachability status from an uploaded callgraph."""

    name = "reachability"

    is_post_processor = True

    depends_on = ["trivy", "grype", "osv", "deps_dev"]

    requires_callgraph = True

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
            "message": "Reachability analysis runs as post-processing on vulnerability findings",
            "findings": [],
        }
