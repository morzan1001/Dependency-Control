"""
ISO/IEC 19790 compliance framework — algorithm-level.

Wraps FIPS 140-3 (the two standards are technically aligned via ISO 19790:2012
Annex D <-> FIPS 140-3 mapping). Exposes the same controls but with ISO-style
identifiers and name.
"""

from typing import List

from app.schemas.compliance import ControlDefinition, FrameworkEvaluation, ReportFramework
from app.services.compliance.frameworks.base import EvaluationInput, evaluate_framework
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework


class Iso19790Framework:
    key = ReportFramework.ISO_19790
    name = "ISO/IEC 19790 (Algorithm-level Conformance)"
    version = "2012 (as aligned with FIPS 140-3)"
    source_url = "https://www.iso.org/standard/52906.html"
    disclaimer = (
        "Algorithm-level conformance only, mapped from FIPS 140-3 approved "
        "functions via ISO/IEC 19790:2012 Annex D. Module-level certification "
        "(e.g., via ISO/IEC 24759) is out of scope."
    )

    def __init__(self):
        self._fips = Fips1403Framework()

    @property
    def controls(self) -> List[ControlDefinition]:
        iso_controls: List[ControlDefinition] = []
        for c in self._fips.controls:
            iso_id = c.control_id.replace("FIPS-140-3-", "ISO-19790-")
            iso_controls.append(ControlDefinition(
                control_id=iso_id,
                title=c.title,
                description=c.description,
                severity=c.severity,
                remediation=c.remediation,
                maps_to_rule_ids=c.maps_to_rule_ids,
                maps_to_finding_types=c.maps_to_finding_types,
                custom_evaluator=c.custom_evaluator,
            ))
        return iso_controls

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)
