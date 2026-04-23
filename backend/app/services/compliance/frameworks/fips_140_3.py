"""
FIPS 140-3 — algorithm-level conformance only.

This framework does NOT check module-level CMVP certification. The title-page
disclaimer communicates that caveat. Controls check whether any detected
algorithm appears in the disallowed set from NIST SP 800-140C/D/F.
"""

from functools import cached_property
from pathlib import Path
from typing import List

import yaml

from app.models.finding import FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition, ControlResult, ControlStatus,
    FrameworkEvaluation, ReportFramework,
)
from app.services.compliance.frameworks.base import (
    EvaluationInput, evaluate_framework,
)

_DATA_PATH = (
    Path(__file__).resolve().parent.parent
    / "data" / "fips_approved_functions.yaml"
)


class Fips1403Framework:
    key = ReportFramework.FIPS_140_3
    name = "FIPS 140-3 (Algorithm-level Conformance)"
    version = "2019"
    source_url = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf"
    disclaimer = (
        "Algorithm-level conformance only. Module-level CMVP certification "
        "status is out of scope of this report."
    )

    @cached_property
    def _data(self) -> dict:
        with _DATA_PATH.open() as f:
            return yaml.safe_load(f) or {}

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        disallowed = (self._data.get("disallowed") or {})
        out: List[ControlDefinition] = []
        for category, algos in disallowed.items():
            title = f"Disallowed {category.replace('_', ' ')}"
            out.append(ControlDefinition(
                control_id=f"FIPS-140-3-{category.upper()}",
                title=title,
                description=(
                    f"No crypto asset may use an algorithm in the disallowed "
                    f"{category} list per NIST SP 800-140C/D/F. "
                    f"Disallowed set: {', '.join(algos)}"
                ),
                severity=Severity.HIGH,
                remediation=(
                    f"Replace disallowed {category} algorithms with members "
                    f"of the approved set."
                ),
                maps_to_rule_ids=[],
                maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM],
                custom_evaluator=_make_disallowed_evaluator(algos, category, title),
            ))
        out.append(ControlDefinition(
            control_id="FIPS-140-3-RSA-MIN-2048",
            title="RSA minimum key size",
            description="Per NIST SP 800-140D, RSA keys must be at least 2048 bits.",
            severity=Severity.HIGH,
            remediation="Rotate any RSA keys shorter than 2048 bits.",
            maps_to_rule_ids=["nist-131a-rsa-min-2048"],
            maps_to_finding_types=[FindingType.CRYPTO_WEAK_KEY],
        ))
        out.append(ControlDefinition(
            control_id="FIPS-140-3-ECDSA-APPROVED-CURVES",
            title="ECDSA approved curves",
            description=(
                "Per NIST SP 800-140D, ECDSA signatures must use one of the "
                "approved curves: P-256, P-384, P-521."
            ),
            severity=Severity.HIGH,
            remediation=(
                "Re-issue ECDSA keys using an approved NIST curve "
                "(P-256, P-384, or P-521)."
            ),
            maps_to_rule_ids=[],
            maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM],
        ))
        return out

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)


def _make_disallowed_evaluator(algos: List[str], category: str, title: str):
    """Return a custom evaluator that walks crypto_assets and flags direct
    use of any algorithm name in the disallowed list."""
    norm_disallowed = {a.upper() for a in algos}

    def evaluator(data: EvaluationInput) -> ControlResult:
        hits_bom_refs: List[str] = []
        hits_names: List[str] = []
        for asset in data.crypto_assets:
            name = getattr(asset, "name", None) or \
                   (asset.get("name") if isinstance(asset, dict) else None)
            if not name:
                continue
            if name.upper() in norm_disallowed:
                hits_names.append(name)
                bom_ref = (getattr(asset, "bom_ref", None)
                           or (asset.get("bom_ref") if isinstance(asset, dict) else None))
                if bom_ref:
                    hits_bom_refs.append(bom_ref)
        if hits_names:
            status = ControlStatus.FAILED
        elif data.crypto_assets:
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.NOT_APPLICABLE
        return ControlResult(
            control_id=f"FIPS-140-3-{category.upper()}",
            title=title,
            description=(
                f"Disallowed {category}: {', '.join(algos)}. "
                f"Observed: {', '.join(sorted(set(hits_names))) or 'none'}"
            ),
            status=status,
            severity=Severity.HIGH,
            evidence_finding_ids=[],
            evidence_asset_bom_refs=sorted(set(hits_bom_refs)),
            waiver_reasons=[],
            remediation=(
                f"Replace disallowed {category} algorithms with members of "
                f"the approved set."
            ),
        )
    return evaluator
