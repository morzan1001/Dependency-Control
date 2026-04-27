"""Constants and regex helpers for the license-compliance analyzer.

Contains:
- Obligation string labels (deduplicated for SonarQube S1192).
- SPDX expression splitter regexes.
- The known license-incompatibility table.
- The severity-rank lookup used when picking the least/most restrictive
  alternative inside an SPDX expression.
- The static ``LICENSE_DATABASE`` of recognised SPDX identifiers and their
  metadata.
- The category → stats-key map used for accumulating component category counts.

Lazy lowercase lookup tables for ``LICENSE_DATABASE`` keys and
``LICENSE_ALIASES`` entries are exposed via :func:`get_lowercase_mappings`.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

from app.core.constants import LICENSE_ALIASES
from app.models.finding import Severity
from app.models.license import LicenseCategory, LicenseInfo

# String constants to avoid duplication (SonarQube S1192)
INCLUDE_COPYRIGHT_NOTICE = "Include copyright notice"
INCLUDE_LICENSE_TEXT = "Include license text"
SHARE_SOURCE_OF_MODIFICATIONS = "Share source of library modifications"
USE_GPL_FOR_DERIVATIVE_WORK = "Use GPL for derivative work"
SHARE_COMPLETE_SOURCE_CODE = "Share complete source code"
NETWORK_USE_TRIGGERS_DISCLOSURE = "Network use triggers source disclosure"

SPDX_EXPR_SPLIT = re.compile(r"\s+(?:AND|OR|WITH)\s+")
SPDX_OR_SPLIT = re.compile(r"\s+OR\s+")
SPDX_AND_SPLIT = re.compile(r"\s+AND\s+")

# Known license incompatibilities: (license_a, license_b) → explanation
# Both directions are checked automatically
LICENSE_INCOMPATIBILITIES: Dict[tuple, str] = {
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
SEVERITY_RANK: Dict[Optional[str], int] = {
    None: 0,  # No issue (permissive/public domain)
    Severity.INFO.value: 1,
    Severity.LOW.value: 2,
    Severity.MEDIUM.value: 3,
    Severity.HIGH.value: 4,
    Severity.CRITICAL.value: 5,
}


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


# Map license categories to stats keys
CATEGORY_STAT_KEY: Dict[LicenseCategory, str] = {
    LicenseCategory.PERMISSIVE: "permissive",
    LicenseCategory.PUBLIC_DOMAIN: "permissive",
    LicenseCategory.WEAK_COPYLEFT: "weak_copyleft",
    LicenseCategory.STRONG_COPYLEFT: "strong_copyleft",
    LicenseCategory.NETWORK_COPYLEFT: "network_copyleft",
    LicenseCategory.PROPRIETARY: "proprietary",
}


# Lazy lowercase lookup tables (built on first access)
_license_db_lower: Optional[Dict[str, str]] = None
_alias_lower: Optional[Dict[str, str]] = None


def get_lowercase_mappings() -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return (db_lower, alias_lower) lookup tables for case-insensitive matching.

    The tables are built lazily on first invocation and cached at module level.
    """
    global _license_db_lower, _alias_lower
    if _license_db_lower is None:
        _license_db_lower = {k.lower(): k for k in LICENSE_DATABASE.keys()}
    if _alias_lower is None:
        _alias_lower = {k.lower(): v for k, v in LICENSE_ALIASES.items()}
    return _license_db_lower, _alias_lower
