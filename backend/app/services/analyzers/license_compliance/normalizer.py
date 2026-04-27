"""Pure helpers for SPDX license normalization and expression parsing.

These helpers consult :data:`LICENSE_DATABASE` / :data:`LICENSE_ALIASES`
and return normalized identifiers, license tuples, or parsed
SPDX OR/AND group structures. They contain no analyzer state.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.constants import LICENSE_ALIASES, UNKNOWN_LICENSE_PATTERNS

from .constants import (
    LICENSE_DATABASE,
    SPDX_AND_SPLIT,
    SPDX_EXPR_SPLIT,
    SPDX_OR_SPLIT,
    get_lowercase_mappings,
)


def normalize_license(lic_id: str) -> str:
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
    if lic_id in LICENSE_DATABASE:
        return lic_id

    # Use pre-computed lowercase mappings for O(1) case-insensitive matching
    db_lower, alias_lower = get_lowercase_mappings()
    lic_lower = lic_id.lower()

    # Try case-insensitive alias match
    if lic_lower in alias_lower:
        return alias_lower[lic_lower]

    # Try case-insensitive database match
    if lic_lower in db_lower:
        return db_lower[lic_lower]

    return lic_id


def extract_licenses(component: Dict[str, Any]) -> List[Tuple[str, Optional[str]]]:
    """Extract license identifiers and URLs from a component.

    Returns a flat list of (license_id, url) tuples. For SPDX expression
    handling, use the expression-aware helpers which preserve OR/AND semantics.
    """
    licenses: List[Tuple[str, Optional[str]]] = []

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
                for lic_id in SPDX_EXPR_SPLIT.split(expr):
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
        if SPDX_EXPR_SPLIT.search(direct_license):
            for lic_id in SPDX_EXPR_SPLIT.split(direct_license):
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


def has_spdx_expression(component: Dict[str, Any]) -> Optional[str]:
    """Return the SPDX expression string if the component has an OR-expression."""
    for lic_entry in component.get("licenses", []):
        if "expression" in lic_entry:
            expr = lic_entry["expression"]
            if expr and expr.upper() not in UNKNOWN_LICENSE_PATTERNS:
                if SPDX_OR_SPLIT.search(expr):
                    return str(expr)

    direct_license = component.get("license")
    if isinstance(direct_license, str) and SPDX_OR_SPLIT.search(direct_license):
        return direct_license

    return None


def parse_spdx_expression(expr: str) -> List[List[str]]:
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
    or_parts = SPDX_OR_SPLIT.split(expr)
    result: List[List[str]] = []
    for or_part in or_parts:
        or_part = or_part.strip("() ")
        if not or_part:
            continue
        # Each OR alternative may contain AND-connected licenses
        and_parts = SPDX_AND_SPLIT.split(or_part)
        group: List[str] = []
        for and_part in and_parts:
            lic_id = and_part.strip("() ")
            if lic_id:
                group.append(lic_id)
        if group:
            result.append(group)
    return result if result else [[expr.strip()]]
