from typing import Dict, Any
from .base import Analyzer

class LicenseAnalyzer(Analyzer):
    name = "license_compliance"
    
    # Default policy
    DENY_LIST = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "WTFPL"]
    WARN_LIST = ["LGPL-2.1", "LGPL-3.0", "MPL-2.0"]

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        components = sbom.get("components", [])
        issues = []

        for component in components:
            licenses = component.get("licenses", [])
            for lic_entry in licenses:
                # CycloneDX structure: licenses: [{license: {id: "MIT"}}, {expression: "..."}]
                lic_id = lic_entry.get("license", {}).get("id")
                lic_name = lic_entry.get("license", {}).get("name")
                
                current_lic = lic_id or lic_name
                
                if not current_lic:
                    continue

                if any(bad in current_lic for bad in self.DENY_LIST):
                    issues.append({
                        "component": component.get("name"),
                        "version": component.get("version"),
                        "license": current_lic,
                        "severity": "CRITICAL",
                        "message": "Forbidden license detected"
                    })
                elif any(warn in current_lic for warn in self.WARN_LIST):
                    issues.append({
                        "component": component.get("name"),
                        "version": component.get("version"),
                        "license": current_lic,
                        "severity": "WARNING",
                        "message": "Restricted license detected"
                    })

        return {"license_issues": issues}
