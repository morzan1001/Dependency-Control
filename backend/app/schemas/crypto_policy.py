"""
Crypto-policy rule schema.

CryptoRule is the unit of matching: it has matchers (what crypto it identifies)
and a finding_type + default_severity (what to emit when it matches).
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoPrimitive


class CryptoPolicySource(str, Enum):
    NIST_SP_800_131A = "nist-sp-800-131a"
    BSI_TR_02102 = "bsi-tr-02102"
    CNSA_2_0 = "cnsa-2.0"
    NIST_PQC = "nist-pqc"
    CUSTOM = "custom"


class CryptoRule(BaseModel):
    rule_id: str = Field(..., description="Stable identifier for the rule (e.g. 'nist-131a-md5')")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="Explanation of what this rule detects and why")
    finding_type: FindingType = Field(..., description="Finding type emitted when this rule matches")
    default_severity: Severity = Field(..., description="Default severity applied to findings from this rule")

    match_primitive: Optional[CryptoPrimitive] = Field(None, description="Restrict matching to this cryptographic primitive")
    match_name_patterns: List[str] = Field(default_factory=list, description="Glob patterns matched case-insensitively against asset name/variant")
    match_min_key_size_bits: Optional[int] = Field(None, description="Match if asset.key_size_bits < this threshold (weak key detection)")
    match_curves: List[str] = Field(default_factory=list, description="Match if asset.curve is in this list")
    match_protocol_versions: List[str] = Field(default_factory=list, description="Match if (protocol_type, version) combines to one of these strings (case-insensitive)")
    quantum_vulnerable: Optional[bool] = Field(None, description="When true, match if primitive is PKE/SIGNATURE/KEM and name is in match_name_patterns")

    enabled: bool = Field(True, description="Whether the rule is active for analysis")
    source: CryptoPolicySource = Field(..., description="Which standards body or origin this rule comes from")
    references: List[str] = Field(default_factory=list, description="URLs to supporting standards or documentation")

    model_config = ConfigDict(use_enum_values=True)
