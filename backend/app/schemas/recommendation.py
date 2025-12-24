"""
Recommendation Schema Definitions

Data classes for the recommendation engine output structures.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RecommendationType(str, Enum):
    """Types of remediation recommendations."""

    # Vulnerability-related
    BASE_IMAGE_UPDATE = "base_image_update"
    DIRECT_DEPENDENCY_UPDATE = "direct_dependency_update"
    TRANSITIVE_FIX_VIA_PARENT = "transitive_fix_via_parent"
    NO_FIX_AVAILABLE = "no_fix_available"
    CONSIDER_WAIVER = "consider_waiver"
    # Secret-related
    ROTATE_SECRETS = "rotate_secrets"
    REMOVE_SECRETS = "remove_secrets"
    # SAST-related
    FIX_CODE_SECURITY = "fix_code_security"
    # IAC-related
    FIX_INFRASTRUCTURE = "fix_infrastructure"
    # License-related
    LICENSE_COMPLIANCE = "license_compliance"
    # Quality-related
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    CRITICAL_RISK = "critical_risk"  # Combined vuln + scorecard risk
    # Dependency Health & Hygiene
    OUTDATED_DEPENDENCY = "outdated_dependency"
    VERSION_FRAGMENTATION = "version_fragmentation"
    DEV_IN_PRODUCTION = "dev_in_production"
    UNMAINTAINED_PACKAGE = "unmaintained_package"
    # Trend-based
    RECURRING_VULNERABILITY = "recurring_vulnerability"
    REGRESSION_DETECTED = "regression_detected"
    # Dependency Graph
    DEEP_DEPENDENCY_CHAIN = "deep_dependency_chain"
    DUPLICATE_FUNCTIONALITY = "duplicate_functionality"
    # Cross-Project
    CROSS_PROJECT_PATTERN = "cross_project_pattern"
    SHARED_VULNERABILITY = "shared_vulnerability"
    
    # Critical Hotspots - highest priority issues requiring immediate action
    CRITICAL_HOTSPOT = "critical_hotspot"  # Package with multiple severe issues
    KNOWN_EXPLOIT = "known_exploit"  # KEV or known exploit available
    RANSOMWARE_RISK = "ransomware_risk"  # Used in ransomware campaigns
    ACTIVELY_EXPLOITED = "actively_exploited"  # Currently being exploited in wild
    
    # Supply Chain Risks
    MALWARE_DETECTED = "malware_detected"  # OSS malware found
    TYPOSQUAT_DETECTED = "typosquat_detected"  # Potential typosquatting package
    HASH_MISMATCH = "hash_mismatch"  # Package integrity issue
    EOL_DEPENDENCY = "eol_dependency"  # End-of-life dependency
    
    # Quick Wins - high impact, low effort fixes
    QUICK_WIN = "quick_win"  # Easy fix with high impact
    SINGLE_UPDATE_MULTI_FIX = "single_update_multi_fix"  # One update fixes many issues
    
    # Risk Aggregation
    TOXIC_DEPENDENCY = "toxic_dependency"  # Package with multiple risk factors
    ATTACK_SURFACE_REDUCTION = "attack_surface_reduction"  # Remove unnecessary deps


class Priority(str, Enum):
    """Recommendation priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class FindingInfo:
    """Generic information about any finding."""

    finding_id: str
    finding_type: str  # vulnerability, secret, sast, iac, license, quality
    severity: str
    component: str  # package name or file path
    version: Optional[str] = None
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    cve_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityInfo:
    """Specific information about a vulnerability finding."""

    finding_id: str
    cve_id: str
    severity: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    description: Optional[str] = None
    source_type: str = "unknown"  # image or application
    
    # EPSS/KEV/Reachability fields for intelligent prioritization
    epss_score: Optional[float] = None  # 0.0 to 1.0
    is_kev: bool = False  # In CISA KEV catalog
    kev_ransomware: bool = False  # Known ransomware use
    is_reachable: Optional[bool] = None  # None = unknown, True = reachable, False = unreachable
    reachability_level: Optional[str] = None  # confirmed, likely, unknown, unreachable
    risk_score: Optional[float] = None  # Adjusted risk score (0-100)

    @property
    def is_fixable(self) -> bool:
        return self.fixed_version is not None
    
    @property
    def is_actionable(self) -> bool:
        """Returns True if this vulnerability should be prioritized for action."""
        # Actionable if: (KEV or high EPSS) AND (reachable or unknown reachability)
        is_exploitable = self.is_kev or (self.epss_score and self.epss_score >= 0.1)
        is_reachable_or_unknown = self.is_reachable is None or self.is_reachable is True
        return is_exploitable and is_reachable_or_unknown
    
    @property
    def is_deprioritized(self) -> bool:
        """Returns True if this vulnerability can be safely deprioritized."""
        # Deprioritized if: unreachable OR (low EPSS and not KEV)
        if self.is_reachable is False:
            return True
        if not self.is_kev and (self.epss_score is None or self.epss_score < 0.01):
            return True
        return False


@dataclass
class Recommendation:
    """A remediation recommendation."""

    type: RecommendationType
    priority: Priority
    title: str
    description: str
    impact: Dict[str, int]  # {critical: X, high: Y, ...}
    affected_components: List[str]
    action: Dict[str, Any]  # Specific action details
    effort: str = "medium"  # low, medium, high
    affected_projects: List[Dict[str, Any]] = field(
        default_factory=list
    )  # [{id, name}]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "affected_components": self.affected_components,
            "action": self.action,
            "effort": self.effort,
            "affected_projects": self.affected_projects,
        }
