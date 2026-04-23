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
from typing import Any, Dict, List, Optional, Tuple

from app.core.constants import LICENSE_ALIASES, UNKNOWN_LICENSE_PATTERNS
from app.models.finding import Severity
from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LicenseCategory,
    LicenseInfo,
    LicensePolicy,
    LibraryUsage,
)

from .base import Analyzer

# String constants to avoid duplication (SonarQube S1192)
INCLUDE_COPYRIGHT_NOTICE = "Include copyright notice"
INCLUDE_LICENSE_TEXT = "Include license text"
SHARE_SOURCE_OF_MODIFICATIONS = "Share source of library modifications"
USE_GPL_FOR_DERIVATIVE_WORK = "Use GPL for derivative work"
SHARE_COMPLETE_SOURCE_CODE = "Share complete source code"
NETWORK_USE_TRIGGERS_DISCLOSURE = "Network use triggers source disclosure"

_SPDX_EXPR_SPLIT = re.compile(r"\s+(?:AND|OR|WITH)\s+")
_SPDX_OR_SPLIT = re.compile(r"\s+OR\s+")
_SPDX_AND_SPLIT = re.compile(r"\s+AND\s+")

# Known license incompatibilities: (license_a, license_b) → explanation
# Both directions are checked automatically
_LICENSE_INCOMPATIBILITIES: Dict[tuple, str] = {
    (
        "GPL-2.0-only",
        "GPL-3.0-only",
    ): "GPL-2.0-only and GPL-3.0-only are not compatible — code cannot satisfy both simultaneously.",
    ("GPL-2.0-only", "GPL-3.0"): "GPL-2.0-only cannot be combined with GPL-3.0 code.",
    ("GPL-2.0-only", "AGPL-3.0"): "GPL-2.0-only is not compatible with AGPL-3.0.",
    ("GPL-2.0-only", "AGPL-3.0-only"): "GPL-2.0-only is not compatible with AGPL-3.0-only.",
    ("CDDL-1.0", "GPL-2.0"): "CDDL-1.0 and GPL-2.0 are incompatible due to conflicting copyleft terms.",
    ("CDDL-1.0", "GPL-2.0-only"): "CDDL-1.0 and GPL-2.0-only are incompatible.",
    ("CDDL-1.0", "GPL-3.0"): "CDDL-1.0 and GPL-3.0 are incompatible due to conflicting copyleft terms.",
    ("CDDL-1.0", "GPL-3.0-only"): "CDDL-1.0 and GPL-3.0-only are incompatible.",
    ("EPL-1.0", "GPL-2.0"): "EPL-1.0 is not compatible with GPL-2.0.",
    ("EPL-1.0", "GPL-2.0-only"): "EPL-1.0 is not compatible with GPL-2.0-only.",
    ("EPL-1.0", "GPL-3.0"): "EPL-1.0 is not compatible with GPL-3.0.",
    ("SSPL-1.0", "GPL-2.0"): "SSPL-1.0 is not compatible with any GPL version.",
    ("SSPL-1.0", "GPL-3.0"): "SSPL-1.0 is not compatible with any GPL version.",
    ("SSPL-1.0", "AGPL-3.0"): "SSPL-1.0 is not compatible with AGPL-3.0.",
}

# Severity rank for choosing the least/most restrictive license in OR/AND expressions
_SEVERITY_RANK = {
    None: 0,  # No issue (permissive/public domain)
    Severity.INFO.value: 1,
    Severity.LOW.value: 2,
    Severity.MEDIUM.value: 3,
    Severity.HIGH.value: 4,
    Severity.CRITICAL.value: 5,
}


def _check_pair_conflict(a: Dict[str, str], b: Dict[str, str], seen: set) -> Optional[Dict[str, Any]]:
    """Check if two component-license entries conflict. Returns an issue dict or None."""
    if a["license"] == b["license"]:
        return None

    pair = tuple(sorted([a["license"], b["license"]]))
    if pair in seen:
        return None

    explanation = _LICENSE_INCOMPATIBILITIES.get((a["license"], b["license"])) or _LICENSE_INCOMPATIBILITIES.get(
        (b["license"], a["license"])
    )
    if not explanation:
        return None

    seen.add(pair)
    return {
        "component": f"{a['component']} + {b['component']}",
        "version": f"{a['version']} / {b['version']}",
        "license": f"{a['license']} / {b['license']}",
        "license_url": None,
        "severity": Severity.HIGH.value,
        "category": "license_incompatibility",
        "message": f"License conflict: {a['license']} and {b['license']}",
        "explanation": (
            f"{explanation}\n\n"
            f"Component A: {a['component']}@{a['version']} ({a['license']})\n"
            f"Component B: {b['component']}@{b['version']} ({b['license']})"
        ),
        "recommendation": (
            "These licenses cannot coexist in the same distributed work. Options:\n"
            "• Replace one of the conflicting components with an alternative\n"
            "• Check if a dual-licensed or 'or-later' variant resolves the conflict\n"
            "• Isolate the components into separate processes/services"
        ),
        "obligations": [],
        "risks": [explanation],
        "purl": a["purl"],
    }


class LicenseAnalyzer(Analyzer):
    name = "license_compliance"

    # Pre-computed lowercase lookup tables (built lazily)
    _license_db_lower: Optional[Dict[str, str]] = None
    _alias_lower: Optional[Dict[str, str]] = None

    @classmethod
    def _get_lowercase_mappings(cls) -> tuple[Dict[str, str], Dict[str, str]]:
        """Get or build lowercase lookup tables for O(1) case-insensitive matching."""
        if cls._license_db_lower is None:
            cls._license_db_lower = {k.lower(): k for k in cls.LICENSE_DATABASE.keys()}
        if cls._alias_lower is None:
            cls._alias_lower = {k.lower(): v for k, v in LICENSE_ALIASES.items()}
        return cls._license_db_lower, cls._alias_lower

    # Comprehensive license database with context
    LICENSE_DATABASE: Dict[str, LicenseInfo] = {
        "MIT": LicenseInfo(
            spdx_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            name="MIT License",
            description="Very permissive license allowing almost any use with attribution.",
            obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
            compatible_with_proprietary=True,
        ),
        "Apache-2.0": LicenseInfo(
            spdx_id="Apache-2.0",
            category=LicenseCategory.PERMISSIVE,
            name="Apache License 2.0",
            description="Permissive license with patent grant protection.",
            obligations=[
                INCLUDE_COPYRIGHT_NOTICE,
                INCLUDE_LICENSE_TEXT,
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
            obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
            compatible_with_proprietary=True,
        ),
        "BSD-3-Clause": LicenseInfo(
            spdx_id="BSD-3-Clause",
            category=LicenseCategory.PERMISSIVE,
            name="BSD 3-Clause License",
            description="Permissive license with non-endorsement clause.",
            obligations=[
                INCLUDE_COPYRIGHT_NOTICE,
                INCLUDE_LICENSE_TEXT,
                "No endorsement without permission",
            ],
            compatible_with_proprietary=True,
        ),
        "ISC": LicenseInfo(
            spdx_id="ISC",
            category=LicenseCategory.PERMISSIVE,
            name="ISC License",
            description="Simplified permissive license similar to MIT.",
            obligations=[INCLUDE_COPYRIGHT_NOTICE],
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
                SHARE_SOURCE_OF_MODIFICATIONS,
                "Allow relinking (for dynamic linking)",
                INCLUDE_LICENSE_TEXT,
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
            obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Allow relinking"],
            risks=["Static linking may trigger full GPL terms"],
            compatible_with_proprietary=True,
            requires_source_disclosure=True,
        ),
        "LGPL-2.1-or-later": LicenseInfo(
            spdx_id="LGPL-2.1-or-later",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v2.1 or later",
            description="LGPL 2.1 with option to use later versions.",
            obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Allow relinking"],
            compatible_with_proprietary=True,
            requires_source_disclosure=True,
        ),
        "LGPL-3.0": LicenseInfo(
            spdx_id="LGPL-3.0",
            category=LicenseCategory.WEAK_COPYLEFT,
            name="GNU Lesser General Public License v3.0",
            description="Modern LGPL with better patent protection.",
            obligations=[
                SHARE_SOURCE_OF_MODIFICATIONS,
                "Provide installation information",
                INCLUDE_LICENSE_TEXT,
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
            obligations=[SHARE_SOURCE_OF_MODIFICATIONS],
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
            obligations=[SHARE_SOURCE_OF_MODIFICATIONS],
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
                INCLUDE_LICENSE_TEXT,
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
        "GPL-2.0": LicenseInfo(
            spdx_id="GPL-2.0",
            category=LicenseCategory.STRONG_COPYLEFT,
            name="GNU General Public License v2.0",
            description="Strong copyleft - entire derivative work must use GPL when distributed.",
            obligations=[
                "Share complete source code of derivative work",
                USE_GPL_FOR_DERIVATIVE_WORK,
                INCLUDE_LICENSE_TEXT,
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
            obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
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
            obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
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
                SHARE_COMPLETE_SOURCE_CODE,
                USE_GPL_FOR_DERIVATIVE_WORK,
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
            obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
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
            obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
            risks=[],
            compatible_with_proprietary=False,
            requires_attribution=True,
            requires_source_disclosure=True,
            viral=True,
            network_clause=False,
        ),
        "AGPL-3.0": LicenseInfo(
            spdx_id="AGPL-3.0",
            category=LicenseCategory.NETWORK_COPYLEFT,
            name="GNU Affero General Public License v3.0",
            description="GPL-3.0 extended to network services - must share source if users interact over network.",
            obligations=[
                SHARE_COMPLETE_SOURCE_CODE,
                "Provide source access to network users",
                "Use AGPL for derivative work",
            ],
            risks=[
                NETWORK_USE_TRIGGERS_DISCLOSURE,
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
            risks=[NETWORK_USE_TRIGGERS_DISCLOSURE],
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
            risks=[NETWORK_USE_TRIGGERS_DISCLOSURE],
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
            obligations=[INCLUDE_COPYRIGHT_NOTICE],
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
            obligations=[INCLUDE_COPYRIGHT_NOTICE],
            risks=[],
            compatible_with_proprietary=True,
            requires_attribution=True,
            requires_source_disclosure=False,
            viral=False,
            network_clause=False,
        ),
    }

    # Aliases and variations
    # Map license categories to stats keys
    _CATEGORY_STAT_KEY = {
        LicenseCategory.PERMISSIVE: "permissive",
        LicenseCategory.PUBLIC_DOMAIN: "permissive",
        LicenseCategory.WEAK_COPYLEFT: "weak_copyleft",
        LicenseCategory.STRONG_COPYLEFT: "strong_copyleft",
        LicenseCategory.NETWORK_COPYLEFT: "network_copyleft",
        LicenseCategory.PROPRIETARY: "proprietary",
    }

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
        ignore_dev = settings.get("ignore_dev_dependencies", True)
        ignore_transitive = settings.get("ignore_transitive", False)

        # Build LicensePolicy from settings.
        # Precedence: settings (already merged from analyzer_settings.license_compliance by engine)
        # falls back to legacy top-level "license_policy" key for backward compat.
        policy_raw = settings.get("license_policy", {})
        if not policy_raw and any(k in settings for k in ("distribution_model", "deployment_model", "library_usage")):
            # New-style: settings come directly from analyzer_settings["license_compliance"]
            policy_raw = settings
        policy = LicensePolicy(
            distribution_model=DistributionModel(policy_raw.get("distribution_model", "distributed")),
            deployment_model=DeploymentModel(policy_raw.get("deployment_model", "network_facing")),
            library_usage=LibraryUsage(policy_raw.get("library_usage", "mixed")),
            allow_strong_copyleft=policy_raw.get("allow_strong_copyleft", settings.get("allow_strong_copyleft", False)),
            allow_network_copyleft=policy_raw.get(
                "allow_network_copyleft", settings.get("allow_network_copyleft", False)
            ),
        )

        components = self._get_components(sbom, parsed_components)
        issues: List[Dict[str, Any]] = []

        stats = {
            "total_components": len(components),
            "permissive": 0,
            "weak_copyleft": 0,
            "strong_copyleft": 0,
            "network_copyleft": 0,
            "proprietary": 0,
            "unknown": 0,
            "skipped": 0,
        }

        for component in components:
            self._analyze_component(
                component,
                stats,
                issues,
                ignore_dev=ignore_dev,
                ignore_transitive=ignore_transitive,
                policy=policy,
            )

        # Cross-dependency license compatibility check
        compatibility_issues = self._check_license_compatibility(components, ignore_dev)
        issues.extend(compatibility_issues)

        return {"license_issues": issues, "summary": stats}

    def _analyze_component(
        self,
        component: Dict[str, Any],
        stats: Dict[str, int],
        issues: List[Dict[str, Any]],
        *,
        ignore_dev: bool,
        ignore_transitive: bool,
        policy: LicensePolicy,
    ) -> None:
        """Analyze a single component for license compliance."""
        comp_scope = (component.get("scope") or "").lower()

        if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
            stats["skipped"] += 1
            return

        is_transitive = not component.get("properties", {}).get("direct", True)
        if ignore_transitive and is_transitive:
            stats["skipped"] += 1
            return

        comp_name = component.get("name", "unknown")
        comp_version = component.get("version", "unknown")
        comp_purl = component.get("purl", "")

        # Check for SPDX OR expressions — use expression-aware evaluation
        spdx_expr = self._has_spdx_expression(component)
        if spdx_expr:
            or_groups = self._parse_spdx_expression(spdx_expr)
            # Track stats for the best choice
            self._track_expression_stats(or_groups, stats)
            issue = self._evaluate_expression(
                comp_name,
                comp_version,
                comp_purl,
                or_groups,
                policy,
            )
            if issue:
                issue["spdx_expression"] = spdx_expr
                self._apply_transitive_adjustment(issue, is_transitive)
                if self._should_include_finding(issue, is_transitive):
                    issues.append(issue)
            return

        # Standard per-license evaluation (no OR expression)
        licenses = self._extract_licenses(component)
        if not licenses:
            stats["unknown"] += 1
            return

        for lic_id, lic_url in licenses:
            normalized = self._normalize_license(lic_id)
            license_info = self.LICENSE_DATABASE.get(normalized)

            if not license_info:
                stats["unknown"] += 1
                continue

            stat_key = self._CATEGORY_STAT_KEY.get(license_info.category)
            if stat_key:
                stats[stat_key] += 1

            issue = self._evaluate_license(
                component=comp_name,
                version=comp_version,
                license_info=license_info,
                lic_url=lic_url,
                purl=comp_purl,
                policy=policy,
            )
            if issue:
                self._apply_transitive_adjustment(issue, is_transitive)
                if self._should_include_finding(issue, is_transitive):
                    issues.append(issue)

    def _track_expression_stats(self, or_groups: List[List[str]], stats: Dict[str, int]) -> None:
        """Track license category stats for the best OR alternative."""
        # Find the least restrictive OR group to track
        best_rank = 999
        best_licenses: List[str] = []
        for group in or_groups:
            worst_rank = 0
            for lic_id in group:
                normalized = self._normalize_license(lic_id)
                info = self.LICENSE_DATABASE.get(normalized)
                if info:
                    cat_rank = {
                        LicenseCategory.PERMISSIVE: 0,
                        LicenseCategory.PUBLIC_DOMAIN: 0,
                        LicenseCategory.WEAK_COPYLEFT: 1,
                        LicenseCategory.STRONG_COPYLEFT: 2,
                        LicenseCategory.NETWORK_COPYLEFT: 3,
                        LicenseCategory.PROPRIETARY: 4,
                    }.get(info.category, 5)
                    worst_rank = max(worst_rank, cat_rank)
            if worst_rank < best_rank:
                best_rank = worst_rank
                best_licenses = group

        for lic_id in best_licenses:
            normalized = self._normalize_license(lic_id)
            info = self.LICENSE_DATABASE.get(normalized)
            if info:
                stat_key = self._CATEGORY_STAT_KEY.get(info.category)
                if stat_key:
                    stats[stat_key] += 1

    @staticmethod
    def _apply_transitive_adjustment(issue: Dict[str, Any], is_transitive: bool) -> None:
        """Reduce severity for transitive dependencies.

        Transitive dependencies pose less direct risk because:
        - The direct dependency may abstract away the transitive's license obligations
        - Dynamic linking/usage patterns may not trigger copyleft
        """
        if not is_transitive:
            return

        issue["is_transitive"] = True
        severity = issue.get("severity")

        # Downgrade severity by one level for transitive deps
        downgrade_map = {
            Severity.CRITICAL.value: Severity.HIGH.value,
            Severity.HIGH.value: Severity.MEDIUM.value,
            Severity.MEDIUM.value: Severity.LOW.value,
        }
        new_severity = downgrade_map.get(severity)
        if new_severity:
            issue["effective_severity"] = issue.get("effective_severity") or severity
            issue["severity"] = new_severity
            existing_reason = issue.get("context_reason", "")
            transitive_note = "Severity reduced: transitive dependency (not directly included)."
            issue["context_reason"] = (
                f"{existing_reason} {transitive_note}".strip() if existing_reason else transitive_note
            )

    @staticmethod
    def _should_include_finding(issue: Dict[str, Any], is_transitive: bool) -> bool:
        """Determine if a finding should be included in results.

        Skip INFO-level findings for transitive dependencies — they add noise
        without actionable value.
        """
        if is_transitive and issue.get("severity") in (
            Severity.INFO.value,
            Severity.LOW.value,
        ):
            return False
        return True

    def _check_license_compatibility(
        self,
        components: List[Dict[str, Any]],
        ignore_dev: bool,
    ) -> List[Dict[str, Any]]:
        """Check for known license incompatibilities across all components."""
        component_licenses = self._collect_component_licenses(components, ignore_dev)
        return self._find_license_conflicts(component_licenses)

    def _collect_component_licenses(
        self,
        components: List[Dict[str, Any]],
        ignore_dev: bool,
    ) -> List[Dict[str, str]]:
        """Collect resolved licenses per non-dev component."""
        result: List[Dict[str, str]] = []
        for comp in components:
            comp_scope = (comp.get("scope") or "").lower()
            if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
                continue
            for lic_id, _ in self._extract_licenses(comp):
                normalized = self._normalize_license(lic_id)
                if normalized in self.LICENSE_DATABASE:
                    result.append(
                        {
                            "component": comp.get("name", "unknown"),
                            "version": comp.get("version", "unknown"),
                            "license": normalized,
                            "purl": comp.get("purl", ""),
                        }
                    )
        return result

    @staticmethod
    def _find_license_conflicts(
        component_licenses: List[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        """Find known incompatibilities between license pairs."""
        issues: List[Dict[str, Any]] = []
        seen_conflicts: set = set()

        for i, a in enumerate(component_licenses):
            for b in component_licenses[i + 1 :]:
                conflict = _check_pair_conflict(a, b, seen_conflicts)
                if conflict:
                    issues.append(conflict)

        return issues

    def _extract_licenses(self, component: Dict[str, Any]) -> List[Tuple[str, Optional[str]]]:
        """Extract license identifiers and URLs from a component.

        Returns a flat list of (license_id, url) tuples. For SPDX expression
        handling, use _extract_license_expressions() which preserves OR/AND semantics.
        """
        licenses = []

        for lic_entry in component.get("licenses", []):
            # CycloneDX structure
            if "license" in lic_entry:
                lic = lic_entry["license"]
                lic_id = lic.get("id") or lic.get("name")
                lic_url = lic.get("url")
                if lic_id and lic_id.upper() not in UNKNOWN_LICENSE_PATTERNS:
                    licenses.append((lic_id, lic_url))

            # SPDX expression — delegate to expression parser
            if "expression" in lic_entry:
                expr = lic_entry["expression"]
                if expr and expr.upper() not in UNKNOWN_LICENSE_PATTERNS:
                    for lic_id in _SPDX_EXPR_SPLIT.split(expr):
                        lic_id = lic_id.strip("() ")
                        if lic_id:
                            licenses.append((lic_id, None))

        # Also check direct license field (parsed components / SPDX format)
        direct_license = component.get("license")
        license_url = component.get("license_url")
        if (
            isinstance(direct_license, str)
            and direct_license.strip()
            and direct_license.upper() not in UNKNOWN_LICENSE_PATTERNS
        ):
            if _SPDX_EXPR_SPLIT.search(direct_license):
                for lic_id in _SPDX_EXPR_SPLIT.split(direct_license):
                    lic_id = lic_id.strip("() ")
                    if lic_id:
                        licenses.append((lic_id, license_url))
            elif "," in direct_license:
                for lic_id in direct_license.split(","):
                    lic_id = lic_id.strip()
                    if lic_id:
                        licenses.append((lic_id, license_url))
            else:
                licenses.append((direct_license, license_url))

        return licenses

    def _parse_spdx_expression(self, expr: str) -> List[List[str]]:
        """Parse an SPDX expression into OR-groups of AND-connected licenses.

        Returns a list of OR-alternatives, where each alternative is a list of
        AND-connected license IDs. The caller should pick the least restrictive
        OR-alternative.

        Examples:
            "MIT OR Apache-2.0"       → [["MIT"], ["Apache-2.0"]]
            "GPL-2.0 AND Classpath"   → [["GPL-2.0", "Classpath"]]
            "MIT OR (GPL-2.0 AND Classpath)" → [["MIT"], ["GPL-2.0", "Classpath"]]
            "MIT"                     → [["MIT"]]
        """
        # Strip WITH exceptions (e.g. "GPL-2.0 WITH Classpath-exception-2.0")
        # WITH modifies the preceding license but doesn't add a new one
        expr = re.sub(r"\s+WITH\s+\S+", "", expr)

        # Split by OR first (lowest precedence in SPDX)
        or_parts = _SPDX_OR_SPLIT.split(expr)
        result = []
        for or_part in or_parts:
            or_part = or_part.strip("() ")
            if not or_part:
                continue
            # Each OR alternative may contain AND-connected licenses
            and_parts = _SPDX_AND_SPLIT.split(or_part)
            group = []
            for and_part in and_parts:
                lic_id = and_part.strip("() ")
                if lic_id:
                    group.append(lic_id)
            if group:
                result.append(group)
        return result if result else [[expr.strip()]]

    def _evaluate_expression(
        self,
        comp_name: str,
        comp_version: str,
        comp_purl: str,
        or_groups: List[List[str]],
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate an SPDX expression by choosing the least restrictive OR-alternative.

        For OR: pick the alternative with the lowest severity (user can choose).
        For AND within an alternative: pick the highest severity (all apply).
        """
        best_issue: Optional[Dict[str, Any]] = None
        best_severity_rank = 999

        for and_group in or_groups:
            # Evaluate all AND-connected licenses — worst (highest severity) wins
            worst_issue: Optional[Dict[str, Any]] = None
            worst_rank = -1

            for lic_id in and_group:
                normalized = self._normalize_license(lic_id)
                license_info = self.LICENSE_DATABASE.get(normalized)
                if not license_info:
                    continue

                issue = self._evaluate_license(
                    component=comp_name,
                    version=comp_version,
                    license_info=license_info,
                    lic_url=None,
                    purl=comp_purl,
                    policy=policy,
                )
                rank = _SEVERITY_RANK.get(issue["severity"] if issue else None, 0)
                if rank > worst_rank:
                    worst_rank = rank
                    worst_issue = issue

            # For OR: pick the least restrictive alternative
            if worst_rank < best_severity_rank:
                best_severity_rank = worst_rank
                best_issue = worst_issue

        return best_issue

    def _has_spdx_expression(self, component: Dict[str, Any]) -> Optional[str]:
        """Check if a component has an SPDX expression and return it."""
        for lic_entry in component.get("licenses", []):
            if "expression" in lic_entry:
                expr = lic_entry["expression"]
                if expr and expr.upper() not in UNKNOWN_LICENSE_PATTERNS:
                    if _SPDX_OR_SPLIT.search(expr):
                        return expr

        direct_license = component.get("license")
        if isinstance(direct_license, str) and _SPDX_OR_SPLIT.search(direct_license):
            return direct_license

        return None

    def _normalize_license(self, lic_id: str) -> str:
        """Normalize a license identifier to SPDX format."""
        if not lic_id:
            return ""

        # Strip metadata suffixes like ;link="..." (common in NuGet/RPM SBOMs)
        # e.g. 'Apache-2.0";link="https://..."' → 'Apache-2.0'
        if ";" in lic_id:
            lic_id = lic_id.split(";", 1)[0]
        # Strip surrounding quotes
        lic_id = lic_id.strip('" ')

        if not lic_id:
            return ""

        # Check aliases first (exact match)
        if lic_id in LICENSE_ALIASES:
            return LICENSE_ALIASES[lic_id]

        # Return as-is if it's already in the database (exact match)
        if lic_id in self.LICENSE_DATABASE:
            return lic_id

        # Use pre-computed lowercase mappings for O(1) case-insensitive matching
        db_lower, alias_lower = self._get_lowercase_mappings()
        lic_lower = lic_id.lower()

        # Try case-insensitive alias match
        if lic_lower in alias_lower:
            return alias_lower[lic_lower]

        # Try case-insensitive database match
        if lic_lower in db_lower:
            return db_lower[lic_lower]

        return lic_id

    def _evaluate_license(
        self,
        component: str,
        version: str,
        license_info: LicenseInfo,
        lic_url: Optional[str],
        purl: str,
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a license and return an issue if problematic.

        Severity is determined by the license category and the project's license policy.
        When a policy reduces the severity, context_reason and effective_severity fields
        are added to the issue for auditability.
        """

        # Permissive and public domain are always fine
        if license_info.category in (
            LicenseCategory.PERMISSIVE,
            LicenseCategory.PUBLIC_DOMAIN,
        ):
            return None

        # Weak copyleft — context: only relevant when library is modified
        if license_info.category == LicenseCategory.WEAK_COPYLEFT:
            return self._evaluate_weak_copyleft(component, version, license_info, lic_url, purl, policy)

        # Strong copyleft — context: only relevant when distributing
        if license_info.category == LicenseCategory.STRONG_COPYLEFT:
            return self._evaluate_strong_copyleft(component, version, license_info, lic_url, purl, policy)

        # Network copyleft — context: only relevant for network-facing services
        if license_info.category == LicenseCategory.NETWORK_COPYLEFT:
            return self._evaluate_network_copyleft(component, version, license_info, lic_url, purl, policy)

        # Proprietary (e.g., NC licenses) — always problematic regardless of context
        if license_info.category == LicenseCategory.PROPRIETARY:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.HIGH,
                category=license_info.category,
                message=f"Non-commercial or proprietary license: {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "This package cannot be used in commercial products. "
                    "Find an alternative or obtain a commercial license."
                ),
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
            )

        return None

    def _evaluate_weak_copyleft(
        self,
        component: str,
        version: str,
        license_info: LicenseInfo,
        lic_url: Optional[str],
        purl: str,
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate weak copyleft licenses (LGPL, MPL, EPL, CDDL).

        Weak copyleft only requires source disclosure for modifications to the library
        itself. Using a library as-is via its public API creates no copyleft obligation.
        """
        if policy.library_usage == LibraryUsage.UNMODIFIED:
            # No obligation when using as-is — skip finding entirely
            return None

        context_reason = None
        if policy.library_usage == LibraryUsage.MODIFIED:
            context_reason = (
                "Library is marked as modified — modifications to this library must be shared under the same license."
            )

        return self._create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.INFO,
            category=license_info.category,
            message=f"Weak copyleft license: {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "This license allows use in proprietary software, but modifications "
                "to this library must be shared under the same license."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
            context_reason=context_reason,
        )

    def _evaluate_strong_copyleft(
        self,
        component: str,
        version: str,
        license_info: LicenseInfo,
        lic_url: Optional[str],
        purl: str,
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate strong copyleft licenses (GPL).

        GPL obligations only trigger upon distribution. Internal-only tools and
        open-source projects have no GPL compliance risk.
        """
        # Internal-only: GPL obligations don't apply (no distribution)
        if policy.distribution_model == DistributionModel.INTERNAL_ONLY:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.INFO,
                category=license_info.category,
                message=f"Strong copyleft license (internal use only): {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "This project is internal-only. GPL obligations only apply when "
                    "distributing software, so no action is required."
                ),
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
                context_reason=(
                    "Severity reduced: project is internal-only, GPL distribution obligations do not apply."
                ),
                effective_severity=Severity.HIGH.value,
            )

        # Open source: GPL is fine, code is already open
        if policy.distribution_model == DistributionModel.OPEN_SOURCE:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.INFO,
                category=license_info.category,
                message=f"Strong copyleft license (open source project): {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "This project is open source. Ensure your project license is GPL-compatible if distributing."
                ),
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
                context_reason=(
                    "Severity reduced: project is open source, GPL source disclosure is already satisfied."
                ),
                effective_severity=Severity.HIGH.value,
            )

        # Distributed: depends on policy allowance
        if policy.allow_strong_copyleft:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.INFO,
                category=license_info.category,
                message=f"Strong copyleft license (allowed by policy): {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "Your policy allows GPL-style licenses. "
                    "Ensure compliance with source disclosure requirements if distributing."
                ),
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
            )

        return self._create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.HIGH,
            category=license_info.category,
            message=f"Strong copyleft license: {license_info.name}",
            explanation=(
                f"{license_info.description}\n\n"
                "IMPORTANT: If you distribute this software (binary or source), "
                "you must also distribute the complete source code of your "
                "entire application under the GPL."
            ),
            recommendation=(
                "Options:\n"
                "• If not distributing (internal use only): GPL obligations don't apply\n"
                "• If open-sourcing your project: License your code under GPL\n"
                "• Otherwise: Find an alternative package with a permissive license"
            ),
            obligations=license_info.obligations,
            risks=license_info.risks,
            purl=purl,
            license_url=lic_url,
        )

    def _evaluate_network_copyleft(
        self,
        component: str,
        version: str,
        license_info: LicenseInfo,
        lic_url: Optional[str],
        purl: str,
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate network copyleft licenses (AGPL, SSPL).

        AGPL/SSPL obligations trigger when users interact over a network.
        CLI tools, batch jobs, desktop apps, and embedded systems are not affected.
        """
        # Non-network deployment: AGPL network clause is irrelevant
        if policy.deployment_model in (
            DeploymentModel.CLI_BATCH,
            DeploymentModel.DESKTOP,
            DeploymentModel.EMBEDDED,
        ):
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.LOW,
                category=license_info.category,
                message=f"Network copyleft license (non-network deployment): {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "This project does not provide network access to users, so the "
                    "AGPL/SSPL network clause does not apply. Standard GPL-like "
                    "distribution obligations still apply if distributing."
                ),
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
                context_reason=(
                    "Severity reduced: project deployment model is "
                    f"'{policy.deployment_model.value}', AGPL/SSPL network clause "
                    "does not apply."
                ),
                effective_severity=Severity.CRITICAL.value,
            )

        # Network-facing + internal only: reduced concern
        if policy.distribution_model == DistributionModel.INTERNAL_ONLY:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.MEDIUM,
                category=license_info.category,
                message=f"Network copyleft license (internal service): {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "This is an internal service. AGPL/SSPL network obligations may "
                    "still apply if internal users interact with the software over a "
                    "network. Review with legal counsel."
                ),
                obligations=license_info.obligations,
                risks=license_info.risks,
                purl=purl,
                license_url=lic_url,
                context_reason=(
                    "Severity reduced: project is internal-only, but network clause may still apply for internal users."
                ),
                effective_severity=Severity.CRITICAL.value,
            )

        # Network-facing + distributed: depends on policy allowance
        if policy.allow_network_copyleft:
            return self._create_issue(
                component=component,
                version=version,
                license_id=license_info.spdx_id,
                severity=Severity.MEDIUM,
                category=license_info.category,
                message=f"Network copyleft license (allowed by policy): {license_info.name}",
                explanation=license_info.description,
                recommendation=(
                    "Your policy allows AGPL-style licenses. Remember: providing "
                    "network access to users triggers source disclosure."
                ),
                obligations=license_info.obligations,
                purl=purl,
                license_url=lic_url,
            )

        return self._create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.CRITICAL,
            category=license_info.category,
            message=f"Network copyleft license: {license_info.name}",
            explanation=(
                f"{license_info.description}\n\n"
                "[CRITICAL] Unlike GPL, AGPL/SSPL obligations are triggered when "
                "users interact with the software over a network, even if you "
                "never distribute binaries. This affects SaaS, web applications, "
                "and APIs."
            ),
            recommendation=(
                "This license is highly problematic for commercial/proprietary use:\n"
                "• Find an alternative package with a permissive license\n"
                "• If no alternative exists, consider isolating this component "
                "as a separate service\n"
                "• Consult with legal counsel before proceeding"
            ),
            obligations=license_info.obligations,
            risks=license_info.risks,
            purl=purl,
            license_url=lic_url,
        )

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
        context_reason: Optional[str] = None,
        effective_severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a license issue with full context.

        Args:
            context_reason: Why the severity was adjusted based on project context.
            effective_severity: What the severity would be without project context (audit trail).
        """
        issue: Dict[str, Any] = {
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
        if context_reason:
            issue["context_reason"] = context_reason
        if effective_severity:
            issue["effective_severity"] = effective_severity
        return issue
