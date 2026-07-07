from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.models.finding import Severity

from .purl_utils import normalize_hash_algorithm


def map_vendor_severity(raw_severity: Optional[str]) -> str:
    """Map a vendor severity label to the internal Severity enum; unknown labels fall back to MEDIUM."""
    return {
        "CRITICAL": Severity.CRITICAL.value,
        "HIGH": Severity.HIGH.value,
        "MEDIUM": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
        "NEGLIGIBLE": Severity.INFO.value,
        "UNKNOWN": Severity.INFO.value,
    }.get((raw_severity or "").upper(), Severity.MEDIUM.value)


class Analyzer(ABC):
    """Base class for all SBOM analyzers; on error, analyze() returns a dict with an "error" key."""

    name: str

    @abstractmethod
    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Analyze an SBOM for security issues; on error returns {"error": ...}."""
        pass

    def _get_components(
        self,
        sbom: Dict[str, Any],
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Return normalized components, preferring pre-parsed ones over raw-SBOM extraction."""
        if parsed_components:
            return parsed_components

        components = []

        # CycloneDX (standard 'components' list)
        if "components" in sbom:
            for comp in sbom["components"]:
                name = comp.get("name")
                if not name or not isinstance(name, str) or not name.strip():
                    continue

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

        # Syft JSON (uses 'artifacts')
        if "artifacts" in sbom:
            for artifact in sbom["artifacts"]:
                name = artifact.get("name")
                if not name or not isinstance(name, str) or not name.strip():
                    continue

                comp = {
                    "name": name,
                    "version": artifact.get("version"),
                    "purl": artifact.get("purl"),
                    "type": artifact.get("type", "library"),
                    "hashes": {},
                    "cpes": [c.get("cpe") for c in artifact.get("cpes", []) if isinstance(c, dict) and c.get("cpe")],
                }
                components.append(comp)
            return components

        # SPDX (uses 'packages')
        if "packages" in sbom:
            for pkg in sbom["packages"]:
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
