"""
Crypto-policy rule schema.

CryptoRule is the unit of matching: it has matchers (what crypto it identifies)
and a finding_type + default_severity (what to emit when it matches).
"""

from collections import Counter
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.constants import POLICY_COMMENT_MAX_LENGTH
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

    # Certificate-Lifecycle thresholds (in days). None = "not used by this rule"
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
        # Without name patterns every PKE/SIGNATURE/KEM asset would match,
        # including post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA).
        if self.quantum_vulnerable is True and not self.match_name_patterns:
            raise ValueError(
                "quantum_vulnerable=True requires match_name_patterns to be set "
                "(otherwise post-quantum primitives like ML-KEM would also match)"
            )
        return self


# The finding types CryptoRuleAnalyzer evaluates; its matchers run for no other type.
RULE_DRIVEN_FINDING_TYPES: frozenset[FindingType] = frozenset(
    {FindingType.CRYPTO_WEAK_ALGORITHM, FindingType.CRYPTO_WEAK_KEY, FindingType.CRYPTO_QUANTUM_VULNERABLE}
)
# The lifecycle analyzer reads a rule of these types for its enabled flag and severity alone.
_CERT_CHECK_TYPES = frozenset(
    {FindingType.CRYPTO_CERT_EXPIRED, FindingType.CRYPTO_CERT_NOT_YET_VALID, FindingType.CRYPTO_CERT_SELF_SIGNED}
)
_EXPIRY_LADDER = ("expiry_critical_days", "expiry_high_days", "expiry_medium_days", "expiry_low_days")
_BOUNDED_LISTS = (
    "match_name_patterns",
    "match_curves",
    "match_protocol_versions",
    "match_cipher_weaknesses",
    "references",
)
_MAX_LIST_ITEMS = 50
# Scan-time matching costs assets x rules on the event loop; the seed set is 28 rules.
_MAX_RULES = 200


def _unevaluable(rule: CryptoRule) -> str | None:
    """Why the rule cannot be stored, or why no analyzer would evaluate it while enabled; None otherwise."""
    oversized = [f for f in _BOUNDED_LISTS if len(getattr(rule, f)) > _MAX_LIST_ITEMS]
    if oversized:
        return f"{', '.join(oversized)} hold more than {_MAX_LIST_ITEMS} entries"
    if not rule.enabled:
        return None
    # Each family of fields is evaluated only on rules of the listed finding types.
    families = [
        finding_types
        for finding_types, used in (
            (
                RULE_DRIVEN_FINDING_TYPES,
                rule.match_name_patterns
                or rule.match_curves
                or rule.match_protocol_versions
                or rule.quantum_vulnerable,
            ),
            ({FindingType.CRYPTO_CERT_EXPIRING_SOON}, any(getattr(rule, f) is not None for f in _EXPIRY_LADDER)),
            ({FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG}, rule.validity_too_long_days is not None),
            ({FindingType.CRYPTO_WEAK_PROTOCOL}, rule.match_cipher_weaknesses),
        )
        if used
    ]
    allowed = set.intersection(*map(set, families)) if families else RULE_DRIVEN_FINDING_TYPES | _CERT_CHECK_TYPES
    if not allowed:
        return "sets fields that no single analyzer evaluates together"
    if rule.finding_type not in allowed:
        return f"finding_type must be one of {sorted(t.value for t in allowed)} for the fields this rule sets"
    # match_min_key_size_bits is a threshold, not a scope: alone it would flag every asset with a key.
    if rule.finding_type in RULE_DRIVEN_FINDING_TYPES and not (
        rule.match_primitive or rule.match_name_patterns or rule.match_curves or rule.match_protocol_versions
    ):
        return "needs match_primitive, match_name_patterns, match_curves or match_protocol_versions"
    ladder = [getattr(rule, f) for f in _EXPIRY_LADDER if getattr(rule, f) is not None]
    if ladder != sorted(ladder):
        return "expiry thresholds must not decrease from critical to low"
    return None


class CryptoRuleIn(CryptoRule):
    """A rule as written through the API. Stored rules keep the lenient CryptoRule so an older
    document still reads."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _evaluable(self) -> "CryptoRuleIn":
        problem = _unevaluable(self)
        if problem:
            raise ValueError(f"rule {self.rule_id!r}: {problem}")
        return self


class CryptoPolicyPutRequest(BaseModel):
    """Full replacement of a policy's rule set. `rules` is required: an absent or misspelled key
    used to read as an empty list, which silently disarmed every crypto analyzer under a 200."""

    rules: list[CryptoRuleIn] = Field(..., max_length=_MAX_RULES)
    comment: str | None = Field(None, max_length=POLICY_COMMENT_MAX_LENGTH)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> "CryptoPolicyPutRequest":
        # Rules are keyed by rule_id downstream, so all but the last of a duplicate would never run.
        counts = Counter(rule.rule_id for rule in self.rules)
        bad = sorted(rule_id for rule_id, count in counts.items() if count > 1 or not rule_id.strip())
        if bad:
            raise ValueError(f"duplicate or empty rule_id(s): {bad}")
        return self
