from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.models.finding import Severity

from .purl_utils import normalize_hash_algorithm


def map_vendor_severity(raw_severity: Optional[str]) -> str:
    """Map a vendor severity label (CRITICAL/HIGH/MEDIUM/LOW/NEGLIGIBLE/UNKNOWN) to the
    internal Severity enum value. Unknown labels fall back to MEDIUM. Shared by the
    CLI vulnerability scanners (grype, trivy) whose maps were byte-for-byte duplicates."""
    return {
        "CRITICAL": Severity.CRITICAL.value,
        "HIGH": Severity.HIGH.value,
        "MEDIUM": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
        "NEGLIGIBLE": Severity.INFO.value,
        "UNKNOWN": Severity.INFO.value,
    }.get((raw_severity or "").upper(), Severity.MEDIUM.value)


class Analyzer(ABC):
    """
    Base class for all SBOM analyzers.

    Error Response Format:
        When an analyzer encounters an error, it should return a dict with:
        - "error": str - Human-readable error message
        - "output": str (optional) - Raw output for debugging (e.g., CLI output)

        Example:
            {"error": "Invalid JSON output from grype", "output": "...raw output..."}

        For partial failures (some components succeeded), continue processing
        and log the error via logger.warning() or logger.debug().
    """

    name: str

    @abstractmethod
    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze an SBOM for security issues.

        Args:
            sbom: Raw SBOM data (CycloneDX, Syft, or SPDX format)
            settings: System settings (API keys, thresholds, etc.)
            parsed_components: Pre-parsed components from sbom_parser (preferred)
                             Each component is a dict with: name, version, purl, type,
                             license, hashes, cpes, etc.

        Returns:
            Dict containing analyzer-specific results. On error, returns:
            {"error": "error message", "output": "optional debug output"}
        """
        pass

    def _get_components(
        self,
        sbom: Dict[str, Any],
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get normalized components for analysis.

        Prefers pre-parsed components from sbom_parser if available.
        Falls back to basic extraction from raw SBOM if needed.

        Args:
            sbom: Raw SBOM data
            parsed_components: Pre-parsed components (preferred - already normalized)

        Returns:
            List of component dicts with at least: name, version, purl, type, hashes
        """
        # Use pre-parsed components if available (preferred path)
        if parsed_components:
            return parsed_components

        # Fallback: basic extraction from raw SBOM
        # This is only used if pre-parsing failed
        components = []

        # 1. CycloneDX (standard 'components' list)
        if "components" in sbom:
            for comp in sbom["components"]:
                # Skip components without a name
                name = comp.get("name")
                if not name or not isinstance(name, str) or not name.strip():
                    continue

                # Normalize hashes from CycloneDX format
                hashes = {}
                for h in comp.get("hashes", []):
                    if isinstance(h, dict) and h.get("alg") and h.get("content"):
                        alg = normalize_hash_algorithm(h["alg"])
                        hashes[alg] = h["content"]

                normalized = {
                    "name": name,
                    "version": comp.get("version"),
                    "purl": comp.get("purl"),
                    "type": comp.get("type", "library"),
                    "hashes": hashes,
                    "cpes": [c.get("cpe") for c in comp.get("cpes", []) if isinstance(c, dict) and c.get("cpe")],
                    "licenses": comp.get("licenses", []),
                }
                components.append(normalized)
            return components

        # 2. Syft JSON (uses 'artifacts') - basic fallback
        if "artifacts" in sbom:
            for artifact in sbom["artifacts"]:
                # Skip artifacts without a name
                name = artifact.get("name")
                if not name or not isinstance(name, str) or not name.strip():
                    continue

                comp = {
                    "name": name,
                    "version": artifact.get("version"),
                    "purl": artifact.get("purl"),
                    "type": artifact.get("type", "library"),
                    "hashes": {},  # Syft hashes need special extraction
                    "cpes": [c.get("cpe") for c in artifact.get("cpes", []) if isinstance(c, dict) and c.get("cpe")],
                }
                components.append(comp)
            return components

        # 3. SPDX (uses 'packages') - basic fallback
        if "packages" in sbom:
            for pkg in sbom["packages"]:
                # Skip packages without a name
                name = pkg.get("name")
                if not name or not isinstance(name, str) or not name.strip():
                    continue

                purl = None
                if "externalRefs" in pkg:
                    for ref in pkg["externalRefs"]:
                        if ref.get("referenceType") == "purl":
                            purl = ref.get("referenceLocator")
                            break

                comp = {
                    "name": name,
                    "version": pkg.get("versionInfo"),
                    "purl": purl,
                    "type": "library",
                    "hashes": {},
                }
                components.append(comp)
            return components

        return []
