"""BSI TR-02102-1 compliance framework."""

from functools import cached_property
from pathlib import Path
from typing import List

from app.schemas.compliance import ControlDefinition, FrameworkEvaluation, ReportFramework
from app.services.compliance.frameworks.base import EvaluationInput, evaluate_framework
from app.services.compliance.frameworks.nist_sp_800_131a import (
    _derive_controls_from_seed,
)

_SEED_PATH = (
    Path(__file__).resolve().parents[3]
    / "services" / "crypto_policy" / "seed" / "bsi_tr_02102.yaml"
)


class BsiTr02102Framework:
    key = ReportFramework.BSI_TR_02102
    name = "BSI TR-02102-1 (Cryptographic Mechanisms: Recommendations and Key Lengths)"
    version = "2024"
    source_url = (
        "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/"
        "TechGuidelines/TG02102/BSI-TR-02102-1.html"
    )
    disclaimer = None

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        return _derive_controls_from_seed(_SEED_PATH, control_id_prefix="BSI-02102")

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)
