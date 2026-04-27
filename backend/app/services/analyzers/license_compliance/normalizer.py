"""Pure helpers for SPDX license normalization and expression parsing."""

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

    # Strip metadata suffixes like ;link="..." common in NuGet/RPM SBOMs.
    if ";" in lic_id:
        lic_id = lic_id.split(";", 1)[0]
    lic_id = lic_id.strip('" ')

    if not lic_id:
        return ""

    if lic_id in LICENSE_ALIASES:
        return LICENSE_ALIASES[lic_id]

    if lic_id in LICENSE_DATABASE:
        return lic_id

    db_lower, alias_lower = get_lowercase_mappings()
    lic_lower = lic_id.lower()

    if lic_lower in alias_lower:
        return alias_lower[lic_lower]

    if lic_lower in db_lower:
        return db_lower[lic_lower]

    return lic_id


def extract_licenses(component: Dict[str, Any]) -> List[Tuple[str, Optional[str]]]:
    """Return flat (license_id, url) tuples; OR/AND semantics need
    has_spdx_expression / parse_spdx_expression."""
    licenses: List[Tuple[str, Optional[str]]] = []

    for lic_entry in component.get("licenses", []):
        if "license" in lic_entry:
            lic = lic_entry["license"]
            lic_id = lic.get("id") or lic.get("name")
            lic_url = lic.get("url")
            if lic_id and lic_id.upper() not in UNKNOWN_LICENSE_PATTERNS:
                licenses.append((lic_id, lic_url))

        if "expression" in lic_entry:
            expr = lic_entry["expression"]
            if expr and expr.upper() not in UNKNOWN_LICENSE_PATTERNS:
                for lic_id in SPDX_EXPR_SPLIT.split(expr):
                    lic_id = lic_id.strip("() ")
                    if lic_id:
                        licenses.append((lic_id, None))

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
    """Return the SPDX expression if the component contains an OR-expression."""
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

    Examples:
        "MIT OR Apache-2.0"              → [["MIT"], ["Apache-2.0"]]
        "GPL-2.0 AND Classpath"          → [["GPL-2.0", "Classpath"]]
        "MIT OR (GPL-2.0 AND Classpath)" → [["MIT"], ["GPL-2.0", "Classpath"]]
    """
    # WITH modifies the preceding license but doesn't add a new one.
    expr = re.sub(r"\s+WITH\s+\S+", "", expr)

    # OR has the lowest precedence in SPDX.
    or_parts = SPDX_OR_SPLIT.split(expr)
    result: List[List[str]] = []
    for or_part in or_parts:
        or_part = or_part.strip("() ")
        if not or_part:
            continue
        and_parts = SPDX_AND_SPLIT.split(or_part)
        group: List[str] = []
        for and_part in and_parts:
            lic_id = and_part.strip("() ")
            if lic_id:
                group.append(lic_id)
        if group:
            result.append(group)
    return result if result else [[expr.strip()]]
