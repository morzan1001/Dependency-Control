"""Data classes and enums for license compliance analysis."""

from dataclasses import dataclass, field
from enum import Enum


class LicenseCategory(str, Enum):
    """License categories based on restrictions."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"  # AGPL, SSPL - triggers on network use
    PUBLIC_DOMAIN = "public_domain"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


# Higher = more restrictive; an unclassified license ranks below permissive. Keyed by the str-valued
# enum, so the category string stored in finding details looks it up directly.
CATEGORY_RESTRICTIVENESS: dict[str, int] = {
    LicenseCategory.UNKNOWN: -1,
    LicenseCategory.PERMISSIVE: 0,
    LicenseCategory.PUBLIC_DOMAIN: 0,
    LicenseCategory.WEAK_COPYLEFT: 1,
    LicenseCategory.STRONG_COPYLEFT: 2,
    LicenseCategory.NETWORK_COPYLEFT: 3,
    LicenseCategory.PROPRIETARY: 4,
}


class DistributionModel(str, Enum):
    """How the project is distributed."""

    INTERNAL_ONLY = "internal_only"  # Not distributed outside the organization
    DISTRIBUTED = "distributed"  # Distributed as binary or source to third parties
    OPEN_SOURCE = "open_source"  # Project itself is open source


class DeploymentModel(str, Enum):
    """How the project is deployed."""

    NETWORK_FACING = "network_facing"  # SaaS, web app, API — users interact over network
    CLI_BATCH = "cli_batch"  # CLI tool, batch job, daemon — no network interaction
    DESKTOP = "desktop"  # Desktop application distributed to users
    EMBEDDED = "embedded"  # Embedded/IoT system


class LibraryUsage(str, Enum):
    """How dependencies are used in the project."""

    UNMODIFIED = "unmodified"  # Libraries used as-is via public API
    MODIFIED = "modified"  # Libraries are forked/patched
    MIXED = "mixed"  # Some modified, some not


@dataclass
class LicenseInfo:
    """Detailed information about a license."""

    spdx_id: str
    category: LicenseCategory
    name: str
    description: str
    obligations: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
