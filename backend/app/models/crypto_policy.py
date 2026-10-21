import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.crypto_asset import CryptoPrimitive
from app.models.finding import FindingType, Severity
from app.models.types import MongoDocument, PyObjectId


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

    match_primitive: CryptoPrimitive | None = Field(
        None, description="Restrict matching to this cryptographic primitive"
    )
    match_name_patterns: list[str] = Field(
        default_factory=list, description="Glob patterns matched case-insensitively against asset name/variant"
    )
    match_min_key_size_bits: int | None = Field(
        None, description="Match if asset.key_size_bits < this threshold (weak key detection)"
    )
    match_curves: list[str] = Field(default_factory=list, description="Match if asset.curve is in this list")
    match_protocol_versions: list[str] = Field(
        default_factory=list,
        description="Match if (protocol_type, version) combines to one of these strings (case-insensitive)",
    )
    quantum_vulnerable: bool | None = Field(
        None,
        description="When true, match if primitive is PKE/SIGNATURE/KEM/KEY-AGREE and name is in match_name_patterns",
    )

    # Certificate-lifecycle thresholds in days; None means the rule does not use one.
    expiry_critical_days: int | None = Field(
        None,
        ge=0,
        description="If cert expires in ≤ this many days, emit CRITICAL severity",
    )
    expiry_high_days: int | None = Field(
        None,
        ge=0,
        description="HIGH severity threshold in days",
    )
    expiry_medium_days: int | None = Field(
        None,
        ge=0,
        description="MEDIUM severity threshold in days",
    )
    expiry_low_days: int | None = Field(
        None,
        ge=0,
        description="LOW / informational threshold in days",
    )
    validity_too_long_days: int | None = Field(
        None,
        ge=0,
        description="Maximum allowed validity period (days); emit CRYPTO_CERT_VALIDITY_TOO_LONG if exceeded",
    )

    match_cipher_weaknesses: list[str] = Field(
        default_factory=list,
        description="Match if any of these weakness tags appear in the parsed cipher-suite entry",
    )

    enabled: bool = Field(True, description="Whether the rule is active for analysis")
    source: CryptoPolicySource = Field(..., description="Which standards body or origin this rule comes from")
    references: list[str] = Field(default_factory=list, description="URLs to supporting standards or documentation")

    model_config = ConfigDict(use_enum_values=True)

    @model_validator(mode="after")
    def _quantum_vulnerable_requires_name_patterns(self) -> "CryptoRule":
        # Without name patterns every PKE/SIGNATURE/KEM asset would match, post-quantum ones (ML-KEM, ML-DSA) included.
        if self.quantum_vulnerable is True and not self.match_name_patterns:
            raise ValueError(
                "quantum_vulnerable=True requires match_name_patterns to be set "
                "(otherwise post-quantum primitives like ML-KEM would also match)"
            )
        return self


class CryptoPolicy(MongoDocument):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
        description="Unique identifier for the policy document",
    )
    scope: Literal["system", "project"] = Field(
        ..., description="Policy scope: 'system' for the seed policy, 'project' for per-project overrides"
    )
    project_id: str | None = Field(None, description="Project ID when scope='project'; None for system policy")
    rules: list[CryptoRule] = Field(default_factory=list, description="Rules carried by this policy document")
    version: int = Field(1, description="Monotonically increasing version for cache invalidation and audit trail")
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Last write timestamp (UTC)"
    )
    updated_by: str | None = Field(
        None, description="User ID of the last person who edited it; None while only the seeder wrote it"
    )
    seed_version: int | None = Field(
        None, description="CURRENT_SEED_VERSION the seeder last applied to the system policy"
    )
