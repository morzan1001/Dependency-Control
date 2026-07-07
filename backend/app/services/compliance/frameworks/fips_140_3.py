"""FIPS 140-3 algorithm-level conformance; no module-level CMVP certification check."""

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
    def data(self) -> Dict[str, Dict[str, List[str]]]:
        """FIPS approved-functions YAML; exposed so derived frameworks (ISO 19790) reuse it."""
        with _DATA_PATH.open() as f:
            loaded = yaml.safe_load(f) or {}
        return loaded if isinstance(loaded, dict) else {}

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        out = build_disallowed_algorithm_controls(self.data, control_id_prefix="FIPS-140-3")
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
        return out

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)


def build_disallowed_algorithm_controls(
    data: Dict[str, Dict[str, List[str]]],
    *,
    control_id_prefix: str,
) -> List[ControlDefinition]:
    """Disallowed-category controls shared by FIPS 140-3 and ISO 19790; control_id_prefix scopes the identifiers."""
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


# Disallowed category -> primitives whose presence makes the control applicable.
_CATEGORY_PRIMITIVES: Dict[str, frozenset] = {
    "hash_functions": frozenset({"hash"}),
    "symmetric_ciphers": frozenset({"block-cipher", "stream-cipher"}),
    "asymmetric": frozenset({"pke", "signature", "kem"}),
}


def _asset_primitive_value(asset: object) -> Optional[str]:
    prim = getattr(asset, "primitive", None)
    if prim is None and isinstance(asset, dict):
        prim = asset.get("primitive")
    if prim is None:
        return None
    return prim.value if hasattr(prim, "value") else str(prim)


def _make_disallowed_evaluator(
    *,
    algos: List[str],
    category: str,
    title: str,
    control_id: str,
) -> Callable[[EvaluationInput], ControlResult]:
    """Custom evaluator flagging direct use of a disallowed algorithm name; control_id captured for derived frameworks."""
    norm_disallowed = {a.upper() for a in algos}
    relevant_primitives = _CATEGORY_PRIMITIVES.get(category, frozenset())

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
        # only applicable when an asset of this category exists
        category_present = any(
            _asset_primitive_value(asset) in relevant_primitives for asset in data.crypto_assets
        )
        if hits_names:
            status = ControlStatus.FAILED
        elif category_present:
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
