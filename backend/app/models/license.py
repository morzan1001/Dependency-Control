"""
License Models

Contains data classes and enums for license compliance analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


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
