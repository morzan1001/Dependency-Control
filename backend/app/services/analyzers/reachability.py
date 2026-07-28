"""Reachability analyzer; the actual enrichment runs in analysis.py post-processing."""

from typing import Any, ClassVar

from .base import Analyzer


class ReachabilityAnalyzer(Analyzer):
    """Post-processing analyzer enriching vulnerability findings with reachability status from an uploaded callgraph."""

    name = "reachability"

    is_post_processor = True

    depends_on: ClassVar[list[str]] = ["trivy", "grype", "osv", "deps_dev"]

    requires_callgraph = True

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
            "message": "Reachability analysis runs as post-processing on vulnerability findings",
            "findings": [],
        }
