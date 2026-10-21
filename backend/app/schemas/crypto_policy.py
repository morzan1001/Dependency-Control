from collections import Counter

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.constants import POLICY_COMMENT_MAX_LENGTH
from app.models.crypto_policy import CryptoRule
from app.models.finding import FindingType


# The finding types evaluate_rules evaluates; its matchers run for no other type.
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
# Scan-time matching costs assets x rules on the event loop; the seed set is 29 rules.
_MAX_RULES = 200


def _unevaluable(rule: CryptoRule) -> str | None:
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
    """Strict for API writes; stored rules keep the lenient CryptoRule so an older document still reads."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _evaluable(self) -> "CryptoRuleIn":
        problem = _unevaluable(self)
        if problem:
            raise ValueError(f"rule {self.rule_id!r}: {problem}")
        return self


class CryptoPolicyPutRequest(BaseModel):
    """Replaces the whole rule set; ``rules`` is required, as reading an absent key as [] disarms every analyzer."""

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
