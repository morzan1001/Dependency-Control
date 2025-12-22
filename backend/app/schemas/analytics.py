"""
Analytics Schema Definitions

Pydantic models and TypedDicts for analytics API endpoints.
These define the response and request structures for analytics operations.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    """Breakdown of findings by severity level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DependencyUsage(BaseModel):
    """Usage statistics for a dependency across projects."""
    name: str
    type: str
    versions: List[str]
    project_count: int
    total_occurrences: int
    has_vulnerabilities: bool
    vulnerability_count: int


class DependencyListItem(BaseModel):
    """Single dependency item with full details for list view."""
    name: str
    version: str
    type: str
    purl: Optional[str] = None
    license: Optional[str] = None
    direct: bool = False
    project_count: int = 1
    project_id: str
    project_name: str
    has_vulnerabilities: bool = False
    vulnerability_count: int = 0
    source_type: Optional[str] = None


class DependencyListResponse(BaseModel):
    """Paginated response for dependency list."""
    items: List[DependencyListItem]
    total: int
    page: int
    size: int
    has_more: bool


class DependencyTreeNode(BaseModel):
    """Node in a dependency tree with findings info."""
    id: str
    name: str
    version: str
    purl: str
    type: str
    direct: bool
    has_findings: bool
    findings_count: int
    findings_severity: Optional[SeverityBreakdown] = None
    children: List["DependencyTreeNode"] = []
    # Source/Origin info
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    locations: List[str] = []


class ImpactAnalysisResult(BaseModel):
    """Result of impact analysis for a component."""
    component: str
    version: str
    affected_projects: int
    total_findings: int
    findings_by_severity: SeverityBreakdown
    recommended_version: Optional[str] = None
    fix_impact_score: float
    affected_project_names: List[str]


class VulnerabilityHotspot(BaseModel):
    """A vulnerability hotspot - component with many findings."""
    component: str
    version: str
    type: str
    finding_count: int
    severity_breakdown: SeverityBreakdown
    affected_projects: List[str]
    first_seen: str


class DependencyTypeStats(BaseModel):
    """Statistics for a dependency type."""
    type: str
    count: int
    percentage: float


class AnalyticsSummary(BaseModel):
    """Summary of analytics across all accessible projects."""
    total_dependencies: int
    total_vulnerabilities: int
    unique_packages: int
    dependency_types: List[DependencyTypeStats]
    severity_distribution: SeverityBreakdown


class DependencyMetadata(BaseModel):
    """Aggregated metadata for a dependency across all projects."""
    
    name: str
    version: str
    type: str
    purl: Optional[str] = None
    
    # Package metadata (dependency-specific, not project-specific)
    description: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    download_url: Optional[str] = None
    group: Optional[str] = None
    
    # License info
    license: Optional[str] = None
    license_url: Optional[str] = None
    license_category: Optional[str] = None
    license_risks: List[str] = []
    license_obligations: List[str] = []
    
    # deps.dev enrichment data
    deps_dev: Optional[Dict[str, Any]] = None
    
    # Aggregated info across projects
    project_count: int = 0
    affected_projects: List[Dict[str, Any]] = []  # [{id, name, direct}]
    total_vulnerability_count: int = 0
    total_finding_count: int = 0
    
    # Enrichment sources
    enrichment_sources: List[str] = []
