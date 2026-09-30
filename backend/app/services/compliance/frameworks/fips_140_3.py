"""FIPS 140-3 and ISO/IEC 19790 algorithm-level conformance; no module-level certification check."""

import functools
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.models.finding import FindingType, Severity
from app.schemas.cbom import QUANTUM_VULNERABLE_PRIMITIVES, CryptoPrimitive
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
)
from app.services.analyzers.crypto.matcher import name_matches
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    _waiver_reasons,
    crypto_assets_verdict,
    evaluate_framework,
    extract_finding_id,
)

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "fips_disallowed_functions.yaml"

# Disallowed category -> primitives whose assets the control judges.
_CATEGORY_PRIMITIVES: dict[str, frozenset[CryptoPrimitive]] = {
    "hash_functions": frozenset({CryptoPrimitive.HASH}),
    "symmetric_ciphers": frozenset({CryptoPrimitive.BLOCK_CIPHER, CryptoPrimitive.STREAM_CIPHER, CryptoPrimitive.AE}),
    "asymmetric": QUANTUM_VULNERABLE_PRIMITIVES,
}


@dataclass
class AlgorithmConformanceFramework:
    """One control per disallowed-function category plus the RSA key-size control."""

    key: ReportFramework
    name: str
    version: str
    disclaimer: str | None
    control_id_prefix: str
    rsa_basis: str

    @functools.cached_property
    def controls(self) -> list[ControlDefinition]:
        out = [
            ControlDefinition(
                control_id=f"{self.control_id_prefix}-{category.upper()}",
                title=f"Disallowed {category.replace('_', ' ')}",
                description=(
                    f"No crypto asset may use an algorithm in the disallowed "
                    f"{category} list per NIST SP 800-140C/D/F. "
                    f"Disallowed set: {', '.join(algos)}"
                ),
                severity=Severity.HIGH,
                remediation=f"Replace disallowed {category} algorithms with approved ones per NIST SP 800-140C/D/F.",
                custom_evaluator=_make_disallowed_evaluator(algos=algos, category=category),
            )
            for category, algos in _disallowed_algorithms().items()
        ]
        out.append(
            ControlDefinition(
                control_id=f"{self.control_id_prefix}-RSA-MIN-2048",
                title="RSA minimum key size",
                description=f"Per {self.rsa_basis}, RSA keys must be at least 2048 bits.",
                severity=Severity.HIGH,
                remediation="Rotate any RSA keys shorter than 2048 bits.",
                maps_to_rule_ids=["nist-131a-rsa-min-2048"],
            )
        )
        return out

    async def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, self.controls, data)


@functools.cache
def _disallowed_algorithms() -> dict[str, list[str]]:
    with _DATA_PATH.open() as f:
        disallowed: dict[str, list[str]] = yaml.safe_load(f)
    return disallowed


def _make_disallowed_evaluator(
    *,
    algos: list[str],
    category: str,
) -> Callable[[ControlDefinition, EvaluationInput], ControlResult]:
    """FAILED when a category asset uses a disallowed algorithm and its weak-algorithm finding is not waived."""
    primitives = _CATEGORY_PRIMITIVES[category]

    def evaluator(control: ControlDefinition, data: EvaluationInput) -> ControlResult:
        in_category = [asset for asset in data.crypto_assets if asset.primitive in primitives]
        hits = [asset for asset in in_category if name_matches(asset, algos)]
        # bom_refs repeat across projects, so only the scan tells whose finding carries the waiver.
        weak = {
            (f.get("scan_id"), (f.get("details") or {}).get("bom_ref")): f
            for f in data.findings
            if f.get("type") == FindingType.CRYPTO_WEAK_ALGORITHM.value
        }
        hit_keys = sorted({(asset.scan_id, asset.bom_ref) for asset in hits})
        matched = [weak[key] for key in hit_keys if key in weak]
        status_reason: str | None = None
        if any(not weak.get(key, {}).get("waived") for key in hit_keys):
            status = ControlStatus.FAILED
        else:
            # Each remaining verdict reads the absence of an unwaived asset off the inventory.
            unflagged = (
                ControlStatus.WAIVED if hits else ControlStatus.PASSED if in_category else ControlStatus.NOT_APPLICABLE
            )
            status, status_reason = crypto_assets_verdict(unflagged, data.coverage)
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            description=(
                f"Disallowed {category}: {', '.join(algos)}. "
                f"Observed: {', '.join(sorted({asset.name for asset in hits})) or 'none'}"
            ),
            status=status,
            severity=control.severity,
            evidence_finding_ids=[extract_finding_id(f) for f in matched],
            evidence_asset_bom_refs=sorted({asset.bom_ref for asset in hits}),
            waiver_reasons=_waiver_reasons(matched),
            remediation=control.remediation,
            status_reason=status_reason,
        )

    return evaluator
