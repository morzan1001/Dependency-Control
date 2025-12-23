"""
Schema Exports

Centralized export of all Pydantic models, TypedDicts, and dataclasses
used across the application.
"""

# Analytics schemas (Pydantic)
from app.schemas.analytics import (
    SeverityBreakdown,
    DependencyUsage,
    DependencyTreeNode,
    ImpactAnalysisResult,
    VulnerabilityHotspot,
    DependencyTypeStats,
    AnalyticsSummary,
    DependencyMetadata,
)

# Finding schemas (TypedDicts)
from app.schemas.finding import (
    VulnerabilityEntry,
    SecretDetails,
    VulnerabilityAggregatedDetails,
    QualityEntry,
    QualityAggregatedDetails,
)

# Enrichment schemas (dataclasses)
from app.schemas.enrichment import DependencyEnrichment

# Recommendation schemas (dataclasses + enums)
from app.schemas.recommendation import (
    RecommendationType,
    Priority,
    FindingInfo,
    VulnerabilityInfo,
    Recommendation,
)

# SBOM schemas (dataclasses + enums)
from app.schemas.sbom import (
    SBOMFormat,
    SourceType,
    ParsedDependency,
    ParsedSBOM,
)

__all__ = [
    # Analytics
    "SeverityBreakdown",
    "DependencyUsage",
    "DependencyTreeNode",
    "ImpactAnalysisResult",
    "VulnerabilityHotspot",
    "DependencyTypeStats",
    "AnalyticsSummary",
    "DependencyMetadata",
    # Finding
    "VulnerabilityEntry",
    "SecretDetails",
    "VulnerabilityAggregatedDetails",
    "QualityEntry",
    "QualityAggregatedDetails",
    # Enrichment
    "DependencyEnrichment",
    # Recommendation
    "RecommendationType",
    "Priority",
    "FindingInfo",
    "VulnerabilityInfo",
    "Recommendation",
    # SBOM
    "SBOMFormat",
    "SourceType",
    "ParsedDependency",
    "ParsedSBOM",
]
