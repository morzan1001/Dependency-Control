"""FIPS 140-3 algorithm-level conformance; no module-level CMVP certification check."""

import functools
from collections.abc import Callable
from pathlib import Path

import yaml

from app.models.finding import Severity
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
    crypto_assets_verdict,
    evaluate_framework,
)

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "fips_approved_functions.yaml"

# Disallowed category -> primitives whose assets the control judges.
_CATEGORY_PRIMITIVES: dict[str, frozenset[CryptoPrimitive]] = {
    "hash_functions": frozenset({CryptoPrimitive.HASH}),
    "symmetric_ciphers": frozenset({CryptoPrimitive.BLOCK_CIPHER, CryptoPrimitive.STREAM_CIPHER, CryptoPrimitive.AE}),
    "asymmetric": QUANTUM_VULNERABLE_PRIMITIVES,
}


class Fips1403Framework:
    key: ReportFramework = ReportFramework.FIPS_140_3
    name: str = "FIPS 140-3 (Algorithm-level Conformance)"
    version: str = "2019"
    source_url: str = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf"
    disclaimer: str | None = (
        "Algorithm-level conformance only. Module-level CMVP certification status is out of scope of this report."
    )

    @functools.cached_property
    def controls(self) -> list[ControlDefinition]:
        return algorithm_conformance_controls("FIPS-140-3", rsa_basis="NIST SP 800-140D")

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)


@functools.cache
def _disallowed_algorithms() -> dict[str, list[str]]:
    with _DATA_PATH.open() as f:
        disallowed: dict[str, list[str]] = yaml.safe_load(f)["disallowed"]
    return disallowed


def algorithm_conformance_controls(control_id_prefix: str, *, rsa_basis: str) -> list[ControlDefinition]:
    """The disallowed-category controls and the RSA key-size control FIPS 140-3 and ISO 19790 share."""
    out: list[ControlDefinition] = []
    for category, algos in _disallowed_algorithms().items():
        title = f"Disallowed {category.replace('_', ' ')}"
        control_id = f"{control_id_prefix}-{category.upper()}"
        out.append(
            ControlDefinition(
                control_id=control_id,
                title=title,
                description=(
                    f"No crypto asset may use an algorithm in the disallowed "
                    f"{category} list per NIST SP 800-140C/D/F. "
                    f"Disallowed set: {', '.join(algos)}"
                ),
                severity=Severity.HIGH,
                remediation=(f"Replace disallowed {category} algorithms with members of the approved set."),
                custom_evaluator=_make_disallowed_evaluator(
                    algos=algos,
                    category=category,
                    title=title,
                    control_id=control_id,
                ),
            )
        )
    out.append(
        ControlDefinition(
            control_id=f"{control_id_prefix}-RSA-MIN-2048",
            title="RSA minimum key size",
            description=f"Per {rsa_basis}, RSA keys must be at least 2048 bits.",
            severity=Severity.HIGH,
            remediation="Rotate any RSA keys shorter than 2048 bits.",
            maps_to_rule_ids=["nist-131a-rsa-min-2048"],
        )
    )
    return out


def _make_disallowed_evaluator(
    *,
    algos: list[str],
    category: str,
    title: str,
    control_id: str,
) -> Callable[[EvaluationInput], ControlResult]:
    """FAILED when an asset of the category's primitives uses a disallowed algorithm by name or variant."""
    primitives = _CATEGORY_PRIMITIVES[category]

    def evaluator(data: EvaluationInput) -> ControlResult:
        in_category = [asset for asset in data.crypto_assets if asset.primitive in primitives]
        hits = [asset for asset in in_category if name_matches(asset, algos)]
        status_reason: str | None = None
        if hits:
            status = ControlStatus.FAILED
        else:
            # Both remaining verdicts read the absence of an asset off the inventory.
            unflagged = ControlStatus.PASSED if in_category else ControlStatus.NOT_APPLICABLE
            status, status_reason = crypto_assets_verdict(unflagged, data.coverage)
        return ControlResult(
            control_id=control_id,
            title=title,
            description=(
                f"Disallowed {category}: {', '.join(algos)}. "
                f"Observed: {', '.join(sorted({asset.name for asset in hits})) or 'none'}"
            ),
            status=status,
            severity=Severity.HIGH,
            evidence_finding_ids=[],
            evidence_asset_bom_refs=sorted({asset.bom_ref for asset in hits}),
            waiver_reasons=[],
            remediation=(f"Replace disallowed {category} algorithms with members of the approved set."),
            status_reason=status_reason,
        )

    return evaluator
