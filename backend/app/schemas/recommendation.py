from dataclasses import dataclass
from enum import Enum
from typing import Any


class RecommendationType(str, Enum):
    BASE_IMAGE_UPDATE = "base_image_update"
    DIRECT_DEPENDENCY_UPDATE = "direct_dependency_update"
    TRANSITIVE_FIX_VIA_PARENT = "transitive_fix_via_parent"
    NO_FIX_AVAILABLE = "no_fix_available"
    ROTATE_SECRETS = "rotate_secrets"
    FIX_CODE_SECURITY = "fix_code_security"
    FIX_INFRASTRUCTURE = "fix_infrastructure"
    LICENSE_COMPLIANCE = "license_compliance"
    LICENSE_DRIFT = "license_drift"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    CRITICAL_RISK = "critical_risk"  # Combined vuln + scorecard risk
    OUTDATED_DEPENDENCY = "outdated_dependency"
    VERSION_FRAGMENTATION = "version_fragmentation"
    DEV_IN_PRODUCTION = "dev_in_production"
    RECURRING_VULNERABILITY = "recurring_vulnerability"
    REGRESSION_DETECTED = "regression_detected"
    DEEP_DEPENDENCY_CHAIN = "deep_dependency_chain"
    DUPLICATE_FUNCTIONALITY = "duplicate_functionality"
    CROSS_PROJECT_PATTERN = "cross_project_pattern"
    SHARED_VULNERABILITY = "shared_vulnerability"

    CRITICAL_HOTSPOT = "critical_hotspot"  # Package with multiple severe issues
    KNOWN_EXPLOIT = "known_exploit"  # KEV or known exploit available
    RANSOMWARE_RISK = "ransomware_risk"
    ACTIVELY_EXPLOITED = "actively_exploited"

    MALWARE_DETECTED = "malware_detected"
    TYPOSQUAT_DETECTED = "typosquat_detected"
    HASH_MISMATCH = "hash_mismatch"
    EOL_DEPENDENCY = "eol_dependency"

    QUICK_WIN = "quick_win"  # Easy fix with high impact
    SINGLE_UPDATE_MULTI_FIX = "single_update_multi_fix"

    TOXIC_DEPENDENCY = "toxic_dependency"  # Package with multiple risk factors
    ATTACK_SURFACE_REDUCTION = "attack_surface_reduction"  # Remove unnecessary deps

    REPLACE_WEAK_ALGORITHM = "replace_weak_algorithm"  # Broken/disallowed primitive
    INCREASE_KEY_SIZE = "increase_key_size"  # Key shorter than policy minimum
    UPGRADE_PROTOCOL = "upgrade_protocol"  # Deprecated TLS / SSH / IPsec version
    PQC_MIGRATION = "pqc_migration"  # Quantum-vulnerable primitive
    ROTATE_CERTIFICATE = "rotate_certificate"  # Expiring or expired cert


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Effort(str, Enum):
    LOW = "low"  # Quick fix, minimal testing needed
    MEDIUM = "medium"  # Some development and testing required
    HIGH = "high"  # Significant development, testing, and coordination needed


@dataclass
class Recommendation:
    type: RecommendationType
    priority: Priority
    title: str
    description: str
    impact: dict[str, Any]  # {critical: X, high: Y, total: Z, ...} + optional metadata
    affected_components: list[str]
    action: dict[str, Any]
    effort: Effort = Effort.MEDIUM
    affected_components_total: int = 0
    # Position in, and size of, its generator's ranked list; both 0 unless the list was cut.
    rank: int = 0
    ranked_out_of: int = 0
