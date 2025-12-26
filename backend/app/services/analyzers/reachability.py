"""
Reachability Analysis Analyzer

Post-processing analyzer that enriches vulnerability findings with reachability data:
- Analyzes if vulnerable code paths are reachable from the application
- Uses callgraph data uploaded via CI/CD pipeline
- Provides confidence scores based on analysis depth

This analyzer runs AFTER vulnerability scanners and requires a callgraph to be uploaded.

Note: This analyzer doesn't process SBOMs directly - it enriches existing findings.
The actual enrichment happens in the post-processing phase of analysis.py.
"""

from typing import Any, Dict, List, Optional

from .base import Analyzer


class ReachabilityAnalyzer(Analyzer):
    """
    Reachability Analysis Analyzer.

    This is a "meta-analyzer" that enriches vulnerability findings with:
    - Reachability status (is the vulnerable code actually called?)
    - Matched vulnerable symbols
    - Analysis confidence scores

    The actual enrichment logic is in services/reachability_enrichment.py
    and is called during post-processing in analysis.py.

    Prerequisites:
    - A callgraph must be uploaded for the project (via callgraph API)
    - Vulnerability findings must exist (from trivy, grype, osv, etc.)

    This class exists to:
    1. Allow users to enable/disable this feature per project
    2. Maintain consistency with other analyzers in the UI
    3. Track that this enrichment was requested/performed
    """

    name = "reachability"

    # Flag indicating this is a post-processing analyzer
    is_post_processor = True

    # Dependencies: which analyzers must run before this one
    depends_on = ["trivy", "grype", "osv", "deps_dev"]

    # Additional requirement: callgraph must be uploaded
    requires_callgraph = True

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        This analyzer doesn't process SBOMs directly.

        The actual enrichment happens in analysis.py's post-processing phase.
        This method returns a placeholder result indicating the analyzer was invoked.
        """
        return {
            "analyzer": self.name,
            "status": "deferred",
            "message": "Reachability analysis runs as post-processing on vulnerability findings",
            "findings": [],
        }
