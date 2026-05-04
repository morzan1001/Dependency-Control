"""
ISO/IEC 19790 compliance framework — algorithm-level.

Wraps FIPS 140-3 (the two standards are technically aligned via ISO 19790:2012
Annex D <-> FIPS 140-3 mapping). Exposes the same controls but with ISO-style
identifiers and name.
"""

from functools import cached_property
from typing import List, Optional

from app.models.finding import FindingType, Severity
from app.schemas.compliance import ControlDefinition, FrameworkEvaluation, ReportFramework
from app.services.compliance.frameworks.base import EvaluationInput, evaluate_framework
from app.services.compliance.frameworks.fips_140_3 import (
    Fips1403Framework,
    build_disallowed_algorithm_controls,
)


class Iso19790Framework:
    key: ReportFramework = ReportFramework.ISO_19790
    name: str = "ISO/IEC 19790 (Algorithm-level Conformance)"
    version: str = "2012 (as aligned with FIPS 140-3)"
    source_url: str = "https://www.iso.org/standard/52906.html"
    disclaimer: Optional[str] = (
        "Algorithm-level conformance only, mapped from FIPS 140-3 approved "
        "functions via ISO/IEC 19790:2012 Annex D. Module-level certification "
        "(e.g., via ISO/IEC 24759) is out of scope."
    )

    def __init__(self) -> None:
        self._fips = Fips1403Framework()

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        # Rebuild the disallowed-category controls with the ISO prefix so
        # the closure-captured control_id matches the framework. Reusing
        # the FIPS controls would carry FIPS-140-3-* identifiers into the
        # ISO report (the closure captures the original prefix).
        out = build_disallowed_algorithm_controls(self._fips.data, control_id_prefix="ISO-19790")
        out.append(
            ControlDefinition(
                control_id="ISO-19790-RSA-MIN-2048",
                title="RSA minimum key size",
                description=("Per ISO/IEC 19790:2012 Annex D and FIPS 140-3, RSA keys must be at least 2048 bits."),
                severity=Severity.HIGH,
                remediation="Rotate any RSA keys shorter than 2048 bits.",
                maps_to_rule_ids=["nist-131a-rsa-min-2048"],
                maps_to_finding_types=[FindingType.CRYPTO_WEAK_KEY],
            )
        )
        return out

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)
