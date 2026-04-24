"""
NIST SP 800-131A Rev.3 compliance framework.

Controls auto-derived from the Phase-1 seed file
`backend/app/services/crypto_policy/seed/nist_sp_800_131a.yaml`.
"""

from functools import cached_property
from pathlib import Path
from typing import List, Optional

import yaml

from app.models.finding import FindingType, Severity
from app.schemas.compliance import ControlDefinition, FrameworkEvaluation, ReportFramework
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    evaluate_framework,
)

_SEED_PATH = Path(__file__).resolve().parents[3] / "services" / "crypto_policy" / "seed" / "nist_sp_800_131a.yaml"


class NistSp800_131aFramework:
    key: ReportFramework = ReportFramework.NIST_SP_800_131A
    name: str = "NIST SP 800-131A (Transitioning Cryptographic Algorithms and Key Lengths)"
    version: str = "Rev.3"
    source_url: str = "https://csrc.nist.gov/pubs/sp/800/131/a/r3/final"
    disclaimer: Optional[str] = None

    @cached_property
    def controls(self) -> List[ControlDefinition]:
        return _derive_controls_from_seed(
            _SEED_PATH,
            control_id_prefix="NIST-131A",
        )

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)


def _derive_controls_from_seed(
    yaml_path: Path,
    *,
    control_id_prefix: str,
) -> List[ControlDefinition]:
    """Turn a seed-rule file into ControlDefinitions.

    Each seed rule -> one control. `control_id` is `<prefix>-<rule_id>`.
    `maps_to_rule_ids=[rule_id]`, `maps_to_finding_types=[finding_type]`.
    """
    with yaml_path.open() as f:
        doc = yaml.safe_load(f) or {}
    controls: List[ControlDefinition] = []
    for rule in doc.get("rules", []):
        rule_id = rule.get("rule_id")
        if not rule_id:
            continue
        ft_value = rule.get("finding_type")
        try:
            finding_type = FindingType(ft_value)
        except ValueError:
            continue
        sev_value = rule.get("default_severity", "MEDIUM")
        try:
            severity = Severity(sev_value)
        except ValueError:
            severity = Severity.MEDIUM
        controls.append(
            ControlDefinition(
                control_id=f"{control_id_prefix}-{rule_id}",
                title=rule.get("name", rule_id),
                description=rule.get("description", "").strip() or rule.get("name", ""),
                severity=severity,
                remediation=rule.get("description", "").strip(),
                maps_to_rule_ids=[rule_id],
                maps_to_finding_types=[finding_type],
            )
        )
    return controls
