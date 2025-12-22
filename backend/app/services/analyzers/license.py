from typing import Dict, Any, List
from .base import Analyzer

class LicenseAnalyzer(Analyzer):
    name = "license_compliance"
    
    # Default policy - Deny list (copyleft, viral licenses)
    DENY_LIST = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", 
                 "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
                 "WTFPL", "SSPL", "SSPL-1.0", "Commons-Clause"]
    
    # Warning list (restrictive but usable in many cases)
    WARN_LIST = ["LGPL-2.1", "LGPL-3.0", "LGPL-2.1-only", "LGPL-2.1-or-later",
                 "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0",
                 "CDDL-1.0", "CDDL-1.1", "CPL-1.0"]
    
    # Unknown/missing license is also a risk
    UNKNOWN_PATTERNS = ["NOASSERTION", "UNKNOWN", "NONE", ""]

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        components = self._get_components(sbom)
        issues = []
        
        # Track components without licenses
        unlicensed_count = 0

        for component in components:
            licenses = component.get("licenses", [])
            comp_name = component.get("name")
            comp_version = component.get("version")
            
            # Check if component has any license
            has_valid_license = False
            
            for lic_entry in licenses:
                # CycloneDX structure: licenses: [{license: {id: "MIT", url: "..."}}, {expression: "..."}]
                lic_id = lic_entry.get("license", {}).get("id")
                lic_name = lic_entry.get("license", {}).get("name")
                lic_url = lic_entry.get("license", {}).get("url")
                lic_expression = lic_entry.get("expression")
                
                current_lic = lic_id or lic_name or lic_expression
                
                if not current_lic or current_lic.upper() in self.UNKNOWN_PATTERNS:
                    continue
                
                has_valid_license = True

                # Check against deny list
                is_denied = any(bad.upper() in current_lic.upper() for bad in self.DENY_LIST)
                if is_denied:
                    issues.append({
                        "component": comp_name,
                        "version": comp_version,
                        "license": current_lic,
                        "license_url": lic_url,
                        "severity": "CRITICAL",
                        "message": "Forbidden license detected - may require code disclosure"
                    })
                    continue
                
                # Check against warning list
                is_warning = any(warn.upper() in current_lic.upper() for warn in self.WARN_LIST)
                if is_warning:
                    issues.append({
                        "component": comp_name,
                        "version": comp_version,
                        "license": current_lic,
                        "license_url": lic_url,
                        "severity": "MEDIUM",
                        "message": "Restricted license detected - review usage restrictions"
                    })
            
            # Track unlicensed components
            if not has_valid_license:
                unlicensed_count += 1
                # Only report if it seems like a real package (not a system lib)
                if comp_name and not comp_name.startswith(("lib", "/")):
                    issues.append({
                        "component": comp_name,
                        "version": comp_version,
                        "license": "UNKNOWN",
                        "license_url": None,
                        "severity": "LOW",
                        "message": "No license information found - review manually"
                    })

        return {
            "license_issues": issues,
            "summary": {
                "total_components": len(components),
                "unlicensed_count": unlicensed_count,
                "issues_count": len(issues)
            }
        }
