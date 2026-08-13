"""Centralized export of schema models used across the application."""

from app.schemas.analytics import (
    AnalyticsSummary,
    DependencyMetadata,
    DependencyTreeNode,
    DependencyTypeStats,
    DependencyUsage,
    ImpactAnalysisResult,
    SeverityBreakdown,
    VulnerabilityHotspot,
)

# Enrichment schemas (dataclasses)
from app.schemas.enrichment import DependencyEnrichment

# Finding schemas (TypedDicts)
from app.schemas.finding import (
    QualityAggregatedDetails,
    QualityEntry,
    VulnerabilityAggregatedDetails,
    VulnerabilityEntry,
)

# Recommendation schemas (dataclasses + enums)
from app.schemas.recommendation import (
    FindingInfo,
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)

# SBOM schemas (dataclasses + enums)
from app.schemas.sbom import ParsedDependency, ParsedSBOM, SBOMFormat, SourceType

__all__ = [
    "AnalyticsSummary",
    # Enrichment
    "DependencyEnrichment",
    "DependencyMetadata",
    "DependencyTreeNode",
    "DependencyTypeStats",
    "DependencyUsage",
    "FindingInfo",
    "ImpactAnalysisResult",
    "ParsedDependency",
    "ParsedSBOM",
    "Priority",
    "QualityAggregatedDetails",
    "QualityEntry",
    "Recommendation",
    # Recommendation
    "RecommendationType",
    # SBOM
    "SBOMFormat",
    # Analytics
    "SeverityBreakdown",
    "SourceType",
    "VulnerabilityAggregatedDetails",
    # Finding
    "VulnerabilityEntry",
    "VulnerabilityHotspot",
    "VulnerabilityInfo",
]
