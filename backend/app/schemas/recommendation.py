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

    @property
    def is_fixable(self) -> bool:
        return self.fixed_version is not None


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
    affected_projects: List[Dict[str, Any]] = field(default_factory=list)  # [{id, name}]

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
