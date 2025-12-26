"""
EPSS/KEV Enrichment Analyzer

Post-processing analyzer that enriches vulnerability findings with:
- EPSS (Exploit Prediction Scoring System) scores from FIRST.org
- CISA KEV (Known Exploited Vulnerabilities) catalog data

This analyzer runs AFTER vulnerability scanners (trivy, grype, osv, etc.)
and enriches their findings with exploitation probability data.

Note: This analyzer doesn't process SBOMs directly - it enriches existing findings.
The actual enrichment happens in the post-processing phase of analysis.py.
"""

from typing import Any, Dict, List, Optional

from .base import Analyzer


class EPSSKEVAnalyzer(Analyzer):
    """
    EPSS/KEV Enrichment Analyzer.

    This is a "meta-analyzer" that enriches vulnerability findings with:
    - EPSS scores (probability of exploitation in next 30 days)
    - CISA KEV data (known exploited vulnerabilities)

    The actual enrichment logic is in services/vulnerability_enrichment.py
    and is called during post-processing in analysis.py.

    This class exists to:
    1. Allow users to enable/disable this feature per project
    2. Maintain consistency with other analyzers in the UI
    3. Track that this enrichment was requested/performed
    """

    name = "epss_kev"

    # Flag indicating this is a post-processing analyzer
    is_post_processor = True

    # Dependencies: which analyzers must run before this one
    depends_on = ["trivy", "grype", "osv", "deps_dev"]

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
            "message": "EPSS/KEV enrichment runs as post-processing on vulnerability findings",
            "findings": [],
        }
