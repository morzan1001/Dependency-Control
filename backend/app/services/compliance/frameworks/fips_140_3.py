"""
FIPS 140-3 — algorithm-level conformance only.

This framework does NOT check module-level CMVP certification. The title-page
disclaimer communicates that caveat. Controls check whether any detected
algorithm appears in the disallowed set from NIST SP 800-140C/D/F.
"""

from functools import cached_property
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

from app.models.finding import FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
)
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    evaluate_framework,
)

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "fips_approved_functions.yaml"


class Fips1403Framework:
    key: ReportFramework = ReportFramework.FIPS_140_3
    name: str = "FIPS 140-3 (Algorithm-level Conformance)"
    version: str = "2019"
    source_url: str = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf"
    disclaimer: Optional[str] = (
        "Algorithm-level conformance only. Module-level CMVP certification status is out of scope of this report."
    )

    @cached_property
    def _data(self) -> Dict[str, Dict[str, List[str]]]:
        with _DATA_PATH.open() as f:
            loaded = yaml.safe_load(f) or {}
        return loaded if isinstance(loaded, dict) else {}

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        out = build_disallowed_algorithm_controls(self._data, control_id_prefix="FIPS-140-3")
        out.append(
            ControlDefinition(
                control_id="FIPS-140-3-RSA-MIN-2048",
                title="RSA minimum key size",
                description="Per NIST SP 800-140D, RSA keys must be at least 2048 bits.",
                severity=Severity.HIGH,
                remediation="Rotate any RSA keys shorter than 2048 bits.",
                maps_to_rule_ids=["nist-131a-rsa-min-2048"],
                maps_to_finding_types=[FindingType.CRYPTO_WEAK_KEY],
            )
        )
        # NOTE: A prior FIPS-140-3-ECDSA-APPROVED-CURVES control was removed
        # here — with an empty maps_to_rule_ids it would either match nothing
        # (always NOT_APPLICABLE) or, if broadened, double-count every weak-
        # algorithm finding globally. Disallowed-category controls above
        # already cover non-approved ECDSA curves via weak_algorithm findings.
        return out

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)


def build_disallowed_algorithm_controls(
    data: Dict[str, Dict[str, List[str]]],
    *,
    control_id_prefix: str,
) -> List[ControlDefinition]:
    """Build the disallowed-category controls shared by FIPS 140-3 and the
    derived ISO 19790 framework. The control_id_prefix lets the caller
    choose between e.g. ``FIPS-140-3-`` and ``ISO-19790-`` so reports
    don't accidentally surface a foreign framework's identifiers."""
    disallowed: Dict[str, List[str]] = data.get("disallowed") or {}
    out: List[ControlDefinition] = []
    for category, algos in disallowed.items():
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
                maps_to_rule_ids=[],
                maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM],
                custom_evaluator=_make_disallowed_evaluator(
                    algos=algos,
                    category=category,
                    title=title,
                    control_id=control_id,
                ),
            )
        )
    return out


def _make_disallowed_evaluator(
    *,
    algos: List[str],
    category: str,
    title: str,
    control_id: str,
) -> Callable[[EvaluationInput], ControlResult]:
    """Return a custom evaluator that walks crypto_assets and flags direct
    use of any algorithm name in the disallowed list. The control_id is
    captured by closure so derived frameworks (ISO 19790) emit the right
    identifier instead of inheriting FIPS' prefix."""
    norm_disallowed = {a.upper() for a in algos}

    def evaluator(data: EvaluationInput) -> ControlResult:
        hits_bom_refs: List[str] = []
        hits_names: List[str] = []
        for asset in data.crypto_assets:
            name = getattr(asset, "name", None) or (asset.get("name") if isinstance(asset, dict) else None)
            if not name:
                continue
            if name.upper() in norm_disallowed:
                hits_names.append(name)
                bom_ref = getattr(asset, "bom_ref", None) or (asset.get("bom_ref") if isinstance(asset, dict) else None)
                if bom_ref:
                    hits_bom_refs.append(bom_ref)
        if hits_names:
            status = ControlStatus.FAILED
        elif data.crypto_assets:
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.NOT_APPLICABLE
        return ControlResult(
            control_id=control_id,
            title=title,
            description=(
                f"Disallowed {category}: {', '.join(algos)}. Observed: {', '.join(sorted(set(hits_names))) or 'none'}"
            ),
            status=status,
            severity=Severity.HIGH,
            evidence_finding_ids=[],
            evidence_asset_bom_refs=sorted(set(hits_bom_refs)),
            waiver_reasons=[],
            remediation=(f"Replace disallowed {category} algorithms with members of the approved set."),
        )

    return evaluator
