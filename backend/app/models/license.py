from dataclasses import dataclass, field
from enum import Enum


class LicenseCategory(str, Enum):
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"  # AGPL, SSPL - triggers on network use
    PUBLIC_DOMAIN = "public_domain"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


# Higher is more restrictive, unknown below permissive; str-enum keys let a stored category string look it up.
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
    INTERNAL_ONLY = "internal_only"
    DISTRIBUTED = "distributed"  # Distributed as binary or source to third parties
    OPEN_SOURCE = "open_source"


class DeploymentModel(str, Enum):
    NETWORK_FACING = "network_facing"  # SaaS, web app, API — users interact over network
    CLI_BATCH = "cli_batch"  # CLI tool, batch job, daemon — no network interaction
    DESKTOP = "desktop"  # Desktop application distributed to users
    EMBEDDED = "embedded"


class LibraryUsage(str, Enum):
    UNMODIFIED = "unmodified"  # Libraries used as-is via public API
    MODIFIED = "modified"  # Libraries are forked/patched
    MIXED = "mixed"


@dataclass
class LicenseInfo:
    spdx_id: str
    category: LicenseCategory
    name: str
    description: str
    obligations: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
