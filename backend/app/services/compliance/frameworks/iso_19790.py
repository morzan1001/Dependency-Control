"""ISO/IEC 19790 algorithm-level framework; wraps FIPS 140-3 with ISO identifiers."""

from functools import cached_property

from app.schemas.compliance import ControlDefinition, FrameworkEvaluation, ReportFramework
from app.services.compliance.frameworks.base import EvaluationInput, evaluate_framework
from app.services.compliance.frameworks.fips_140_3 import algorithm_conformance_controls


class Iso19790Framework:
    key: ReportFramework = ReportFramework.ISO_19790
    name: str = "ISO/IEC 19790 (Algorithm-level Conformance)"
    version: str = "2012 (as aligned with FIPS 140-3)"
    source_url: str = "https://www.iso.org/standard/52906.html"
    disclaimer: str | None = (
        "Algorithm-level conformance only, mapped from FIPS 140-3 approved "
        "functions via ISO/IEC 19790:2012 Annex D. Module-level certification "
        "(e.g., via ISO/IEC 24759) is out of scope."
    )

    @cached_property
    def controls(self) -> list[ControlDefinition]:
        return algorithm_conformance_controls("ISO-19790", rsa_basis="ISO/IEC 19790:2012 Annex D and FIPS 140-3")

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)
