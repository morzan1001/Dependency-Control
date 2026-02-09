from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    SECRET = "secret"
    MALWARE = "malware"
    EOL = "eol"
    IAC = "iac"  # Infrastructure as Code
    SAST = "sast"  # Static Application Security Testing
    SYSTEM_WARNING = "system_warning"
    OUTDATED = "outdated"
    QUALITY = "quality"  # Supply chain quality issues (maintainer risk, etc.)
    OTHER = "other"


class Finding(BaseModel):
    id: str = Field(..., description="Unique identifier for the finding")
    type: FindingType = Field(..., description="Type of finding")
    severity: Severity = Field(..., description="Severity level")
    component: str = Field(..., description="Affected component or file")
    version: Optional[str] = Field(None, description="Affected version")
    description: str = Field(..., description="Short description")
    scanners: List[str] = Field(..., description="List of scanners that detected this")
    details: Dict[str, Any] = Field(default_factory=dict, description="Analyzer-specific details")

    # Additional metadata
    found_in: List[str] = Field(default_factory=list, description="Source files where this was found")
    aliases: List[str] = Field(default_factory=list, description="Alternative IDs (e.g. GHSA vs CVE)")
    related_findings: List[str] = Field(
        default_factory=list,
        description="IDs of related findings (e.g. same CVEs in different packages)",
    )

    # Status fields
    waived: bool = False
    waiver_reason: Optional[str] = None

    class Config:
        use_enum_values = True
