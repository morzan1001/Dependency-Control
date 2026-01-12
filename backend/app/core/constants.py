"""
Shared Constants

Centralized constants used across the application to ensure consistency.
"""

from typing import Dict, Optional

# Severity order for sorting (higher value = more severe)
SEVERITY_ORDER: Dict[str, int] = {
    # Uppercase variants for consistency
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NEGLIGIBLE": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def get_severity_value(severity: Optional[str]) -> int:
    """Get numeric value for severity. Higher = more severe."""
    if not severity:
        return 0
    return SEVERITY_ORDER.get(severity.upper(), 0)


def sort_by_severity(items: list, key: str = "severity", reverse: bool = True) -> list:
    """
    Sort a list of dicts by severity.

    Args:
        items: List of dicts with severity field
        key: The key containing severity value
        reverse: If True, most severe first (default)
    """
    return sorted(
        items,
        key=lambda x: get_severity_value(
            x.get(key) if isinstance(x, dict) else getattr(x, key, None)
        ),
        reverse=reverse,
    )


# EPSS score thresholds based on exploitation probability
EPSS_HIGH_THRESHOLD: float = 0.1  # >= 10% - Very likely to be exploited
EPSS_MEDIUM_THRESHOLD: float = 0.01  # >= 1% - Moderate exploitation risk
EPSS_LOW_THRESHOLD: float = 0.0  # < 1% - Low exploitation risk


# License URL Patterns
# Common license URL patterns to SPDX ID mapping
LICENSE_URL_PATTERNS: Dict[str, str] = {
    # GNU Licenses
    r"gnu\.org/licenses/gpl-3\.0": "GPL-3.0",
    r"gnu\.org/licenses/gpl-2\.0": "GPL-2.0",
    r"gnu\.org/licenses/lgpl-3\.0": "LGPL-3.0",
    r"gnu\.org/licenses/lgpl-2\.1": "LGPL-2.1",
    r"gnu\.org/licenses/lgpl-2\.0": "LGPL-2.0",
    r"gnu\.org/licenses/agpl-3\.0": "AGPL-3.0",
    r"gnu\.org/licenses/fdl": "GFDL-1.3",
    # Apache
    r"apache\.org/licenses/LICENSE-2\.0": "Apache-2.0",
    r"apache\.org/licenses/LICENSE-1\.1": "Apache-1.1",
    # MIT
    r"opensource\.org/licenses/MIT": "MIT",
    r"mit-license\.org": "MIT",
    # BSD
    r"opensource\.org/licenses/BSD-3-Clause": "BSD-3-Clause",
    r"opensource\.org/licenses/BSD-2-Clause": "BSD-2-Clause",
    # Creative Commons
    r"creativecommons\.org/licenses/by/4\.0": "CC-BY-4.0",
    r"creativecommons\.org/licenses/by-sa/4\.0": "CC-BY-SA-4.0",
    r"creativecommons\.org/publicdomain/zero/1\.0": "CC0-1.0",
    # Mozilla
    r"mozilla\.org/MPL/2\.0": "MPL-2.0",
    r"mozilla\.org/MPL/1\.1": "MPL-1.1",
    # Eclipse
    r"eclipse\.org/legal/epl-2\.0": "EPL-2.0",
    r"eclipse\.org/legal/epl-v10": "EPL-1.0",
    # ISC
    r"opensource\.org/licenses/ISC": "ISC",
    # Unlicense
    r"unlicense\.org": "Unlicense",
    # WTFPL
    r"wtfpl\.net": "WTFPL",
    # Zlib
    r"zlib\.net/zlib_license\.html": "Zlib",
}

# License Aliases
# Common license names to SPDX ID mapping
LICENSE_ALIASES: Dict[str, str] = {
    "MIT/X11": "MIT",
    "Expat": "MIT",
    # Apache variations
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "ASL 2.0": "Apache-2.0",
    # BSD variations
    "BSD": "BSD-3-Clause",
    "BSD License": "BSD-3-Clause",
    "BSD-2": "BSD-2-Clause",
    "BSD-3": "BSD-3-Clause",
    "Simplified BSD": "BSD-2-Clause",
    "New BSD": "BSD-3-Clause",
    "Modified BSD": "BSD-3-Clause",
    # GPL variations
    "GPL": "GPL-2.0-or-later",
    "GPLv2": "GPL-2.0",
    "GPLv2+": "GPL-2.0-or-later",
    "GPLv3": "GPL-3.0",
    "GPLv3+": "GPL-3.0-or-later",
    "GPL v2": "GPL-2.0",
    "GPL v3": "GPL-3.0",
    "GNU GPL": "GPL-2.0-or-later",
    "GNU GPLv2": "GPL-2.0",
    "GNU GPLv3": "GPL-3.0",
    # LGPL variations
    "LGPL": "LGPL-2.1-or-later",
    "LGPLv2": "LGPL-2.1",
    "LGPLv2.1": "LGPL-2.1",
    "LGPLv3": "LGPL-3.0",
    "GNU LGPL": "LGPL-2.1-or-later",
    # AGPL variations
    "AGPL": "AGPL-3.0",
    "AGPLv3": "AGPL-3.0",
    "GNU AGPL": "AGPL-3.0",
    # MPL variations
    "MPL": "MPL-2.0",
    "MPL 2.0": "MPL-2.0",
    "Mozilla Public License 2.0": "MPL-2.0",
    # Other
    "Public Domain": "Unlicense",
    "CC0": "CC0-1.0",
    "ISC License": "ISC",
    "Artistic": "Artistic-2.0",
    "zlib/libpng": "Zlib",
    "Boost": "BSL-1.0",
    "PSF": "Python-2.0",
}

# Patterns indicating unknown/missing license
UNKNOWN_LICENSE_PATTERNS = {
    "NOASSERTION",
    "UNKNOWN",
    "NONE",
    "N/A",
    "NOT FOUND",
    "UNLICENSED",
    "SEE LICENSE",
    "CUSTOM",
    "PROPRIETARY",
}

# Project Roles
PROJECT_ROLE_ADMIN = "admin"
PROJECT_ROLE_EDITOR = "editor"
PROJECT_ROLE_VIEWER = "viewer"
PROJECT_ROLES = [PROJECT_ROLE_VIEWER, PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN]

# Team Roles
TEAM_ROLE_OWNER = "owner"
TEAM_ROLE_ADMIN = "admin"
TEAM_ROLE_MEMBER = "member"
TEAM_ROLES = [TEAM_ROLE_MEMBER, TEAM_ROLE_ADMIN, TEAM_ROLE_OWNER]


# ==============================================================================
# RECOMMENDATION ENGINE CONSTANTS
# ==============================================================================

# Weights for calculating risk scores
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
    "UNKNOWN": 0.0,
}

# OS package types that typically come from base images
OS_PACKAGE_TYPES = {"deb", "rpm", "apk", "alpm", "pacman", "dpkg"}

# Application package types managed by package managers
APP_PACKAGE_TYPES = {
    "npm",
    "pypi",
    "maven",
    "gradle",
    "cargo",
    "gem",
    "nuget",
    "golang",
    "go-module",
    "pip",
    "composer",
}

# Common patterns for development dependencies
DEV_DEPENDENCY_PATTERNS = [
    r"jest",
    r"mocha",
    r"chai",
    r"sinon",
    r"enzyme",
    r"testing-library",
    r"eslint",
    r"prettier",
    r"tslint",
    r"stylelint",
    r"webpack-dev",
    r"nodemon",
    r"ts-node",
    r"@types/",
    r"typescript$",
    r"storybook",
    r"chromatic",
    r"cypress",
    r"playwright",
    r"puppeteer",
    r"husky",
    r"lint-staged",
    r"commitlint",
    r"babel-jest",
    r"ts-jest",
]


# Scoring weights for identifying "Quick Win" updates
QUICK_WIN_SCORING_WEIGHTS: Dict[str, int] = {
    "base_per_vuln": 10,
    "critical": 50,
    "high": 20,
    "kev": 100,
    "direct_dep_bonus": 50,
}


# Weights for calculating recommendation priority scores
RECOMMENDATION_SCORING_WEIGHTS: Dict[str, int] = {
    # Base priority scores
    "priority_critical": 10000,
    "priority_high": 1000,
    "priority_medium": 100,
    "priority_low": 10,
    # Impact multipliers
    "impact_critical": 100,
    "impact_high": 50,
    "impact_medium": 20,
    "impact_low": 5,
    # Threat intel bonuses
    "kev_bonus": 500,
    "kev_ransomware_bonus": 250,
    "high_epss_bonus": 200,
    "medium_epss_bonus": 50,
    "active_exploitation_bonus": 300,
}


# Weights for reachability analysis
REACHABILITY_SCORING_WEIGHTS: Dict[str, int] = {
    "critical_bonus": 150,
    "high_bonus": 75,
    "other_bonus": 25,
}

REACHABILITY_MODIFIERS: Dict[str, float] = {
    "high_unreachable_ratio_threshold": 0.8,
    "high_unreachable_penalty": 0.4,
    "medium_unreachable_ratio_threshold": 0.5,
    "medium_unreachable_penalty": 0.7,
}
