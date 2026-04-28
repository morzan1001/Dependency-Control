from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


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
    CRYPTO_WEAK_ALGORITHM = "crypto_weak_algorithm"
    CRYPTO_WEAK_KEY = "crypto_weak_key"
    CRYPTO_QUANTUM_VULNERABLE = "crypto_quantum_vulnerable"
    # Phase 2: Certificate lifecycle findings
    CRYPTO_CERT_EXPIRED = "crypto_cert_expired"
    CRYPTO_CERT_EXPIRING_SOON = "crypto_cert_expiring_soon"
    CRYPTO_CERT_NOT_YET_VALID = "crypto_cert_not_yet_valid"
    CRYPTO_CERT_WEAK_SIGNATURE = "crypto_cert_weak_signature"
    CRYPTO_CERT_WEAK_KEY = "crypto_cert_weak_key"
    CRYPTO_CERT_SELF_SIGNED = "crypto_cert_self_signed"
    CRYPTO_CERT_VALIDITY_TOO_LONG = "crypto_cert_validity_too_long"
    # Phase 2: Protocol weakness
    CRYPTO_WEAK_PROTOCOL = "crypto_weak_protocol"
    # Phase 3: Key management hygiene (crypto-misuse SAST rules)
    CRYPTO_KEY_MANAGEMENT = "crypto_key_management"
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

    model_config = ConfigDict(use_enum_values=True)
