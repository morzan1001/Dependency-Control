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
class LicensePolicy:
    """Project-level license compliance policy that provides context for severity decisions."""

    distribution_model: DistributionModel = DistributionModel.DISTRIBUTED
    deployment_model: DeploymentModel = DeploymentModel.NETWORK_FACING
    library_usage: LibraryUsage = LibraryUsage.MIXED
    allow_strong_copyleft: bool = False
    allow_network_copyleft: bool = False


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
