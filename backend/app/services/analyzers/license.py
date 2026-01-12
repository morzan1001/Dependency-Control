"""
License Compliance Analyzer

Analyzes SBOM components for license compliance issues.
Uses SPDX license identifiers and provides context-aware severity ratings.

License Categories:
- PERMISSIVE: Safe for any use (MIT, Apache-2.0, BSD, ISC, etc.)
- WEAK_COPYLEFT: Requires sharing modifications to the library (LGPL, MPL, EPL)
- STRONG_COPYLEFT: Requires sharing entire work if distributed (GPL, AGPL)
- PROPRIETARY_HOSTILE: Incompatible with closed-source (AGPL, SSPL)
- COMMERCIAL: May require payment/attribution (various commercial licenses)
- UNKNOWN: No license or unrecognized - manual review needed
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.core.constants import LICENSE_ALIASES, UNKNOWN_LICENSE_PATTERNS
from app.models.finding import Severity
from .base import Analyzer


class LicenseCategory(str, Enum):
    """License categories based on restrictions."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"  # AGPL, SSPL - triggers on network use
    PUBLIC_DOMAIN = "public_domain"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


@dataclass
class LicenseInfo:
    """Detailed information about a license."""

    spdx_id: str
    category: LicenseCategory
    name: str
    description: str
    obligations: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    compatible_with_proprietary: bool = False
    requires_attribution: bool = True
    requires_source_disclosure: bool = False
    viral: bool = False
    network_clause: bool = False


class LicenseAnalyzer(Analyzer):
    name = "license_compliance"

    # Comprehensive license database with context
    LICENSE_DATABASE: Dict[str, LicenseInfo] = {
        "MIT": LicenseInfo(
            spdx_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            name="MIT License",
            description="Very permissive license allowing almost any use with attribution.",
            obligations=["Include copyright notice", "Include license text"],
            compatible_with_proprietary=True,
        ),
        "Apache-2.0": LicenseInfo(
            spdx_id="Apache-2.0",
            category=LicenseCategory.PERMISSIVE,
            name="Apache License 2.0",
            description="Permissive license with patent grant protection.",
            obligations=[
                "Include copyright notice",
                "Include license text",
                "State changes",
                "Include NOTICE file if present",
            ],
            compatible_with_proprietary=True,
        ),
        "BSD-2-Clause": LicenseInfo(
            spdx_id="BSD-2-Clause",
            category=LicenseCategory.PERMISSIVE,
            name="BSD 2-Clause License",
            description="Simple permissive license with minimal requirements.",
            obligations=["Include copyright notice", "Include license text"],
            compatible_with_proprietary=True,
        ),
        "BSD-3-Clause": LicenseInfo(
            spdx_id="BSD-3-Clause",
            category=LicenseCategory.PERMISSIVE,
            name="BSD 3-Clause License",
            description="Permissive license with non-endorsement clause.",
            obligations=[
                "Include copyright notice",
                "Include license text",
                "No endorsement without permission",
            ],
            compatible_with_proprietary=True,
        ),
        "ISC": LicenseInfo(
            spdx_id="ISC",
            category=LicenseCategory.PERMISSIVE,
            name="ISC License",
            description="Simplified permissive license similar to MIT.",
            obligations=["Include copyright notice"],
            compatible_with_proprietary=True,
        ),
        "Unlicense": LicenseInfo(
            spdx_id="Unlicense",
            category=LicenseCategory.PUBLIC_DOMAIN,
            name="The Unlicense",
            description="Public domain dedication with no restrictions.",
            risks=["May not be recognized in all jurisdictions"],
            compatible_with_proprietary=True,
            requires_attribution=False,
        ),
        "CC0-1.0": LicenseInfo(
            spdx_id="CC0-1.0",
            category=LicenseCategory.PUBLIC_DOMAIN,
            name="CC0 1.0 Universal",
            description="Public domain dedication by Creative Commons.",
            compatible_with_proprietary=True,
            requires_attribution=False,
        ),
        "0BSD": LicenseInfo(
            spdx_id="0BSD",
            category=LicenseCategory.PUBLIC_DOMAIN,
            name="Zero-Clause BSD",
            description="Public domain equivalent BSD license.",
            compatible_with_proprietary=True,
            requires_attribution=False,
        ),
        "WTFPL": LicenseInfo(
            spdx_id="WTFPL",
            category=LicenseCategory.PUBLIC_DOMAIN,
            name="Do What The F*ck You Want To Public License",
            description="Extremely permissive, essentially public domain.",
            risks=["May not be legally enforceable in all jurisdictions"],
            compatible_with_proprietary=True,
            requires_attribution=False,
        ),
        "LGPL-2.1": LicenseInfo(
            spdx_id="LGPL-2.1",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v2.1",
            description="Allows linking in proprietary software, but library changes must be shared.",
            obligations=[
                "Share source of library modifications",
                "Allow relinking (for dynamic linking)",
                "Include license text",
            ],
            risks=["Static linking may trigger full GPL terms"],
            compatible_with_proprietary=True,
            requires_source_disclosure=True,
        ),
        "LGPL-2.1-only": LicenseInfo(
            spdx_id="LGPL-2.1-only",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v2.1 only",
            description="LGPL 2.1 without the 'or later' option.",
            obligations=["Share source of library modifications", "Allow relinking"],
            risks=["Static linking may trigger full GPL terms"],
            compatible_with_proprietary=True,
            requires_source_disclosure=True,
        ),
        "LGPL-2.1-or-later": LicenseInfo(
            spdx_id="LGPL-2.1-or-later",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v2.1 or later",
            description="LGPL 2.1 with option to use later versions.",
            obligations=["Share source of library modifications", "Allow relinking"],
            compatible_with_proprietary=True,
            requires_source_disclosure=True,
        ),
        "LGPL-3.0": LicenseInfo(
            spdx_id="LGPL-3.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v3.0",
            description="Modern LGPL with better patent protection.",
            obligations=[
                "Share source of library modifications",
                "Provide installation information",
                "Include license text",
            ],
            risks=["Must allow user to replace library version"],
            compatible_with_proprietary=True,
            requires_source_disclosure=True,
        ),
        "LGPL-3.0-only": LicenseInfo(
            spdx_id="LGPL-3.0-only",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v3.0 only",
            description="LGPL 3.0 without the 'or later' option.",
            obligations=["Share source of library modifications"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=False,
            network_clause=False,
        ),
        "LGPL-3.0-or-later": LicenseInfo(
            spdx_id="LGPL-3.0-or-later",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v3.0 or later",
            description="LGPL 3.0 with option to use later versions.",
            obligations=["Share source of library modifications"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=False,
            network_clause=False,
        ),
        "MPL-2.0": LicenseInfo(
            spdx_id="MPL-2.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="Mozilla Public License 2.0",
            description="File-level copyleft - only modified files must be shared.",
            obligations=[
                "Share source of modified files",
                "Include license text",
                "Preserve copyright notices",
            ],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=True,  # Modified files only
            viral=False,
            network_clause=False,
        ),
        "EPL-1.0": LicenseInfo(
            spdx_id="EPL-1.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="Eclipse Public License 1.0",
            description="Weak copyleft with patent grant.",
            obligations=["Share source of modifications"],
            risks=["Patent retaliation clause"],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=False,
            network_clause=False,
        ),
        "EPL-2.0": LicenseInfo(
            spdx_id="EPL-2.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="Eclipse Public License 2.0",
            description="Modern EPL with GPL compatibility option.",
            obligations=["Share source of modifications"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=False,
            network_clause=False,
        ),
        "CDDL-1.0": LicenseInfo(
            spdx_id="CDDL-1.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="Common Development and Distribution License 1.0",
            description="File-level copyleft similar to MPL.",
            obligations=["Share source of modified files"],
            risks=["Incompatible with GPL"],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=False,
            network_clause=False,
        ),
        # ========== STRONG COPYLEFT (Entire work must be shared if distributed) ==========
        "GPL-2.0": LicenseInfo(
            spdx_id="GPL-2.0",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v2.0",
            description="Strong copyleft - entire derivative work must use GPL when distributed.",
            obligations=[
                "Share complete source code of derivative work",
                "Use GPL for derivative work",
                "Include license text",
                "Include installation instructions",
            ],
            risks=[
                "Cannot be combined with proprietary code if distributed",
                "Source code must be provided to recipients",
            ],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        "GPL-2.0-only": LicenseInfo(
            spdx_id="GPL-2.0-only",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v2.0 only",
            description="GPL 2.0 without the 'or later' upgrade option.",
            obligations=["Share complete source code", "Use GPL for derivative work"],
            risks=["Cannot use GPL-3.0-only code"],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        "GPL-2.0-or-later": LicenseInfo(
            spdx_id="GPL-2.0-or-later",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v2.0 or later",
            description="GPL 2.0 with option to use later versions.",
            obligations=["Share complete source code", "Use GPL for derivative work"],
            risks=[],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        "GPL-3.0": LicenseInfo(
            spdx_id="GPL-3.0",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v3.0",
            description="Modern GPL with patent protection and anti-tivoization.",
            obligations=[
                "Share complete source code",
                "Use GPL for derivative work",
                "Provide installation information",
                "No additional restrictions (DRM, etc.)",
            ],
            risks=[
                "Cannot be combined with proprietary code",
                "Anti-tivoization may affect embedded devices",
            ],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        "GPL-3.0-only": LicenseInfo(
            spdx_id="GPL-3.0-only",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v3.0 only",
            description="GPL 3.0 without the 'or later' option.",
            obligations=["Share complete source code", "Use GPL for derivative work"],
            risks=["Incompatible with GPL-2.0-only"],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        "GPL-3.0-or-later": LicenseInfo(
            spdx_id="GPL-3.0-or-later",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v3.0 or later",
            description="GPL 3.0 with option to use later versions.",
            obligations=["Share complete source code", "Use GPL for derivative work"],
            risks=[],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        # ========== NETWORK COPYLEFT (Triggers on network use, not just distribution) ==========
        "AGPL-3.0": LicenseInfo(
            spdx_id="AGPL-3.0",
            category=LicenseCategory.NETWORK_COPYLEFT,
            name="GNU Affero General Public License v3.0",
            description="GPL-3.0 extended to network services - must share source if users interact over network.",
            obligations=[
                "Share complete source code",
                "Provide source access to network users",
                "Use AGPL for derivative work",
            ],
            risks=[
                "Network use triggers source disclosure",
                "SaaS and web services must provide source",
                "Very restrictive for commercial use",
            ],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=True,
        ),
        "AGPL-3.0-only": LicenseInfo(
            spdx_id="AGPL-3.0-only",
            category=LicenseCategory.NETWORK_COPYLEFT,
            name="GNU Affero General Public License v3.0 only",
            description="AGPL 3.0 without the 'or later' option.",
            obligations=["Share source to network users"],
            risks=["Network use triggers source disclosure"],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=True,
        ),
        "AGPL-3.0-or-later": LicenseInfo(
            spdx_id="AGPL-3.0-or-later",
            category=LicenseCategory.NETWORK_COPYLEFT,
            name="GNU Affero General Public License v3.0 or later",
            description="AGPL 3.0 with option to use later versions.",
            obligations=["Share source to network users"],
            risks=["Network use triggers source disclosure"],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=True,
        ),
        "SSPL-1.0": LicenseInfo(
            spdx_id="SSPL-1.0",
            category=LicenseCategory.NETWORK_COPYLEFT,
            name="Server Side Public License v1",
            description="MongoDB's license - even stricter than AGPL for SaaS use.",
            obligations=[
                "Share all service code including management software",
                "Extends to entire service stack",
            ],
            risks=[
                "Extremely restrictive for cloud/SaaS",
                "Not OSI approved",
                "May require sharing unrelated service code",
            ],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=True,
        ),
        # ========== OTHER/SPECIAL ==========
        "CC-BY-4.0": LicenseInfo(
            spdx_id="CC-BY-4.0",
            category=LicenseCategory.PERMISSIVE,
            name="Creative Commons Attribution 4.0",
            description="Attribution required. Typically for non-software content.",
            obligations=["Give appropriate credit", "Indicate if changes were made"],
            risks=["Not designed for software"],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
        "CC-BY-SA-4.0": LicenseInfo(
            spdx_id="CC-BY-SA-4.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="Creative Commons Attribution ShareAlike 4.0",
            description="Attribution + ShareAlike - derivatives must use same license.",
            obligations=["Give credit", "Use same license for derivatives"],
            risks=["Not designed for software", "ShareAlike can be restrictive"],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=True,
            network_clause=False,
        ),
        "CC-BY-NC-4.0": LicenseInfo(
            spdx_id="CC-BY-NC-4.0",
            category=LicenseCategory.PROPRIETARY,
            name="Creative Commons Attribution NonCommercial 4.0",
            description="Cannot be used commercially.",
            obligations=["Give credit", "Non-commercial use only"],
            risks=["Cannot use in commercial products"],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
        "Artistic-2.0": LicenseInfo(
            spdx_id="Artistic-2.0",
            category=LicenseCategory.PERMISSIVE,
            name="Artistic License 2.0",
            description="Perl's license - permissive with some restrictions on modified versions.",
            obligations=[
                "Document modifications",
                "Use different name for modified versions",
            ],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
        "Zlib": LicenseInfo(
            spdx_id="Zlib",
            category=LicenseCategory.PERMISSIVE,
            name="zlib License",
            description="Very permissive license used by zlib compression library.",
            obligations=["Acknowledge in documentation"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
        "BSL-1.0": LicenseInfo(
            spdx_id="BSL-1.0",
            category=LicenseCategory.PERMISSIVE,
            name="Boost Software License 1.0",
            description="Very permissive license from Boost C++ Libraries.",
            obligations=["Include license text in source distributions"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
        "Python-2.0": LicenseInfo(
            spdx_id="Python-2.0",
            category=LicenseCategory.PERMISSIVE,
            name="Python Software Foundation License 2.0",
            description="Python's permissive license.",
            obligations=["Include copyright notice"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
        "PostgreSQL": LicenseInfo(
            spdx_id="PostgreSQL",
            category=LicenseCategory.PERMISSIVE,
            name="PostgreSQL License",
            description="BSD-style permissive license.",
            obligations=["Include copyright notice"],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
    }

    # Aliases and variations
    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze SBOM components for license compliance issues.

        Settings can include:
        - allow_strong_copyleft: bool - Allow GPL-style licenses (default: False)
        - allow_network_copyleft: bool - Allow AGPL/SSPL (default: False)
        - ignore_dev_dependencies: bool - Skip devDependencies (default: True)
        - ignore_transitive: bool - Only check direct deps (default: False)
        """
        settings = settings or {}
        allow_strong_copyleft = settings.get("allow_strong_copyleft", False)
        allow_network_copyleft = settings.get("allow_network_copyleft", False)
        ignore_dev = settings.get("ignore_dev_dependencies", True)
        ignore_transitive = settings.get("ignore_transitive", False)

        components = self._get_components(sbom, parsed_components)
        issues = []

        # Statistics
        stats = {
            "total_components": len(components),
            "permissive": 0,
            "weak_copyleft": 0,
            "strong_copyleft": 0,
            "network_copyleft": 0,
            "unknown": 0,
            "skipped": 0,
        }

        for component in components:
            comp_name = component.get("name", "unknown")
            comp_version = component.get("version", "unknown")
            comp_scope = component.get("scope", "").lower()
            comp_purl = component.get("purl", "")

            # Skip dev dependencies if configured
            if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
                stats["skipped"] += 1
                continue

            # Skip transitive if configured
            # Check via properties or bom-ref patterns
            is_transitive = not component.get("properties", {}).get("direct", True)
            if ignore_transitive and is_transitive:
                stats["skipped"] += 1
                continue

            # Extract licenses
            licenses = self._extract_licenses(component)

            if not licenses:
                stats["unknown"] += 1
                # Only flag as issue for direct dependencies or if specifically requested
                if not is_transitive or not ignore_transitive:
                    issues.append(
                        self._create_issue(
                            component=comp_name,
                            version=comp_version,
                            license_id="UNKNOWN",
                            severity=Severity.LOW,
                            category=LicenseCategory.UNKNOWN,
                            message="No license information found",
                            explanation="This package does not specify a license. This could mean proprietary terms apply, or the maintainer simply forgot to include license information.",
                            recommendation="Contact the package maintainer to clarify licensing, or review the package's source repository for license files.",
                            purl=comp_purl,
                        )
                    )
                continue

            # Analyze each license
            for lic_id, lic_url in licenses:
                normalized = self._normalize_license(lic_id)
                license_info = self.LICENSE_DATABASE.get(normalized)

                if license_info:
                    issue = self._evaluate_license(
                        component=comp_name,
                        version=comp_version,
                        license_info=license_info,
                        lic_url=lic_url,
                        purl=comp_purl,
                        allow_strong_copyleft=allow_strong_copyleft,
                        allow_network_copyleft=allow_network_copyleft,
                    )

                    if issue:
                        issues.append(issue)

                    # Update stats
                    if license_info.category == LicenseCategory.PERMISSIVE:
                        stats["permissive"] += 1
                    elif license_info.category == LicenseCategory.WEAK_COPYLEFT:
                        stats["weak_copyleft"] += 1
                    elif license_info.category == LicenseCategory.STRONG_COPYLEFT:
                        stats["strong_copyleft"] += 1
                    elif license_info.category == LicenseCategory.NETWORK_COPYLEFT:
                        stats["network_copyleft"] += 1
                else:
                    # Unknown license
                    stats["unknown"] += 1
                    issues.append(
                        self._create_issue(
                            component=comp_name,
                            version=comp_version,
                            license_id=lic_id,
                            severity=Severity.INFO,
                            category=LicenseCategory.UNKNOWN,
                            message=f"Unrecognized license: {lic_id}",
                            explanation="This license identifier is not in our database. It may be a custom or uncommon license.",
                            recommendation="Review the license text manually to understand its terms and obligations.",
                            purl=comp_purl,
                            license_url=lic_url,
                        )
                    )

        return {"license_issues": issues, "summary": stats}

    def _extract_licenses(
        self, component: Dict[str, Any]
    ) -> List[Tuple[str, Optional[str]]]:
        """Extract license identifiers and URLs from a component."""
        licenses = []

        for lic_entry in component.get("licenses", []):
            # CycloneDX structure
            if "license" in lic_entry:
                lic = lic_entry["license"]
                lic_id = lic.get("id") or lic.get("name")
                lic_url = lic.get("url")
                if lic_id and lic_id.upper() not in UNKNOWN_LICENSE_PATTERNS:
                    licenses.append((lic_id, lic_url))

            # SPDX expression
            if "expression" in lic_entry:
                expr = lic_entry["expression"]
                if expr and expr.upper() not in UNKNOWN_LICENSE_PATTERNS:
                    # Handle expressions like "MIT OR Apache-2.0"
                    for lic_id in re.split(r"\s+(?:AND|OR|WITH)\s+", expr):
                        lic_id = lic_id.strip("() ")
                        if lic_id:
                            licenses.append((lic_id, None))

        # Also check direct license field (SPDX format)
        direct_license = component.get("license")
        if (
            isinstance(direct_license, str)
            and direct_license.upper() not in UNKNOWN_LICENSE_PATTERNS
        ):
            licenses.append((direct_license, None))

        return licenses

    def _normalize_license(self, lic_id: str) -> str:
        """Normalize a license identifier to SPDX format."""
        if not lic_id:
            return ""

        # Check aliases first
        if lic_id in LICENSE_ALIASES:
            return LICENSE_ALIASES[lic_id]

        # Try case-insensitive alias match
        for alias, spdx in LICENSE_ALIASES.items():
            if alias.lower() == lic_id.lower():
                return spdx

        # Return as-is if it's already in the database
        if lic_id in self.LICENSE_DATABASE:
            return lic_id

        # Try case-insensitive match
        for spdx_id in self.LICENSE_DATABASE.keys():
            if spdx_id.lower() == lic_id.lower():
                return spdx_id

        return lic_id

    def _evaluate_license(
        self,
        component: str,
        version: str,
        license_info: LicenseInfo,
        lic_url: Optional[str],
        purl: str,
        allow_strong_copyleft: bool,
        allow_network_copyleft: bool,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a license and return an issue if problematic."""

        # Permissive and public domain are always fine
        if license_info.category in (
            LicenseCategory.PERMISSIVE,
            LicenseCategory.PUBLIC_DOMAIN,
        ):
            return None

        # Weak copyleft - just informational
        if license_info.category == LicenseCategory.WEAK_COPYLEFT:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.INFO,
                category=license_info.category,
                message=f"Weak copyleft license: {license_info.name}",
                explanation=license_info.description,
                recommendation="This license allows use in proprietary software, but modifications to this library must be shared under the same license.",
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
            )

        # Strong copyleft - depends on policy
        if license_info.category == LicenseCategory.STRONG_COPYLEFT:
            if allow_strong_copyleft:
                return self._create_issue(
                    component=component,
                    version=version,
                    license_id=license_info.spdx_id,
                    severity=Severity.INFO,
                    category=license_info.category,
                    message=f"Strong copyleft license (allowed by policy): {license_info.name}",
                    explanation=license_info.description,
                    recommendation="Your policy allows GPL-style licenses. Ensure compliance with source disclosure requirements if distributing.",
                    obligations=license_info.obligations,
                    purl=purl,
                    license_url=lic_url,
                )
            else:
                return self._create_issue(
                    component=component,
                    version=version,
                    license_id=license_info.spdx_id,
                    severity=Severity.HIGH,
                    category=license_info.category,
                    message=f"Strong copyleft license: {license_info.name}",
                    explanation=f"{license_info.description}\n\nIMPORTANT: If you distribute this software (binary or source), you must also distribute the complete source code of your entire application under the GPL.",
                    recommendation="Options:\n• If not distributing (internal use only): GPL obligations don't apply\n• If open-sourcing your project: License your code under GPL\n• Otherwise: Find an alternative package with a permissive license",
                    obligations=license_info.obligations,
                    risks=license_info.risks,
                    purl=purl,
                    license_url=lic_url,
                )

        # Network copyleft - most restrictive
        if license_info.category == LicenseCategory.NETWORK_COPYLEFT:
            if allow_network_copyleft:
                return self._create_issue(
                    component=component,
                    version=version,
                    license_id=license_info.spdx_id,
                    severity=Severity.MEDIUM,
                    category=license_info.category,
                    message=f"Network copyleft license (allowed by policy): {license_info.name}",
                    explanation=license_info.description,
                    recommendation="Your policy allows AGPL-style licenses. Remember: providing network access to users triggers source disclosure.",
                    obligations=license_info.obligations,
                    purl=purl,
                    license_url=lic_url,
                )
            else:
                return self._create_issue(
                    component=component,
                    version=version,
                    license_id=license_info.spdx_id,
                    severity=Severity.CRITICAL,
                    category=license_info.category,
                    message=f"Network copyleft license: {license_info.name}",
                    explanation=f"{license_info.description}\n\n[CRITICAL] Unlike GPL, AGPL/SSPL obligations are triggered when users interact with the software over a network, even if you never distribute binaries. This affects SaaS, web applications, and APIs.",
                    recommendation="This license is highly problematic for commercial/proprietary use:\n• Find an alternative package with a permissive license\n• If no alternative exists, consider isolating this component as a separate service\n• Consult with legal counsel before proceeding",
                    obligations=license_info.obligations,
                    risks=license_info.risks,
                    purl=purl,
                    license_url=lic_url,
                )

        # Proprietary (e.g., NC licenses)
        if license_info.category == LicenseCategory.PROPRIETARY:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.HIGH,
                category=license_info.category,
                message=f"Non-commercial or proprietary license: {license_info.name}",
                explanation=license_info.description,
                recommendation="This package cannot be used in commercial products. Find an alternative or obtain a commercial license.",
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
            )

        return None

    def _create_issue(
        self,
        component: str,
        version: str,
        license_id: str,
        severity: Severity,
        category: LicenseCategory,
        message: str,
        explanation: str,
        recommendation: str,
        obligations: Optional[List[str]] = None,
        risks: Optional[List[str]] = None,
        purl: Optional[str] = None,
        license_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a license issue with full context."""
        return {
            "component": component,
            "version": version,
            "license": license_id,
            "license_url": license_url,
            "severity": severity.value,
            "category": category.value,
            "message": message,
            "explanation": explanation,
            "recommendation": recommendation,
            "obligations": obligations or [],
            "risks": risks or [],
            "purl": purl,
        }
