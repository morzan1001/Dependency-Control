from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    SECRET = "secret"
    MALWARE = "malware"
    EOL = "eol"
    IAC = "iac" # Infrastructure as Code
    SAST = "sast" # Static Application Security Testing
    SYSTEM_WARNING = "system_warning"
    OUTDATED = "outdated"
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

    # Status fields
    waived: bool = False
    waiver_reason: Optional[str] = None
    
    class Config:
        use_enum_values = True
