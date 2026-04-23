"""CNSA 2.0 compliance framework."""

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
    / "services" / "crypto_policy" / "seed" / "cnsa_2_0.yaml"
)


class Cnsa20Framework:
    key = ReportFramework.CNSA_2_0
    name = "CNSA 2.0 (Commercial National Security Algorithm Suite)"
    version = "2022"
    source_url = (
        "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/"
        "CSA_CNSA_2.0_ALGORITHMS_.PDF"
    )
    disclaimer = None

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        return _derive_controls_from_seed(_SEED_PATH, control_id_prefix="CNSA20")

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)
