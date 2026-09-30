"""Renderer protocol — each format implements render(eval, report) → bytes."""

from datetime import datetime
from typing import Protocol

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import EvaluationCoverage, FrameworkEvaluation, InputCoverage
from app.services.compliance.frameworks.base import NAMES_SHOWN
from app.services.recommendation.common import name_some

_INPUT_COMPLETE = "Evaluated all {in_scope} {subject} in scope."
_INPUT_PARTIAL = (
    "Evaluated {evaluated} of {in_scope} {subject} in scope, a cap of {limit} per report; "
    "the remaining {missing} were not read."
)
_WITHHELD_EXPLANATION = (
    "Every verdict below that would have rested on finding no match in a capped input is reported "
    "as not_evaluated instead. Failures stand — a subset can under-report a violation but cannot "
    "invent one. Narrow the scope and regenerate for a verdict that covers everything."
)
_GAPS_STATEMENT = (
    "Inputs are missing for part of the scope, so every verdict that would have rested on finding "
    "no match is reported as not_evaluated: {gaps}."
)


def _input_statement(coverage: InputCoverage, subject: str) -> str:
    if coverage.complete:
        return _INPUT_COMPLETE.format(in_scope=coverage.in_scope, subject=subject)
    return _INPUT_PARTIAL.format(
        evaluated=coverage.evaluated,
        in_scope=coverage.in_scope,
        limit=coverage.limit,
        subject=subject,
        missing=coverage.in_scope - coverage.evaluated,
    )


def coverage_statement(coverage: EvaluationCoverage) -> str:
    """The sentence a reader needs to know whether the verdicts cover the scope."""
    reads = {
        "findings": coverage.findings,
        "crypto assets": coverage.crypto_assets,
        "migration plan items": coverage.plan_items,
    }
    parts = [_input_statement(read, subject) for subject, read in reads.items() if read is not None]
    if coverage.gaps:
        parts.append(_GAPS_STATEMENT.format(gaps=name_some(coverage.gaps, NAMES_SHOWN)))
    if any(read is not None and not read.complete for read in reads.values()):
        parts.append(_WITHHELD_EXPLANATION)
    return " ".join(parts)


class Renderer(Protocol):
    mime_type: str
    extension: str

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: str | None = None,
    ) -> tuple[bytes, str, str]:
        """Return (artifact_bytes, filename, mime_type)."""
        ...


def build_filename(
    framework_key: str,
    scope: str,
    scope_id: str | None,
    requested_at: datetime,
    extension: str,
) -> str:
    """Construct a filesystem-safe filename, e.g. nist-sp-800-131a_project-p1_20260420T100000Z.pdf."""
    scope_part = f"{scope}" + (f"-{scope_id}" if scope_id else "")
    import re

    scope_part = re.sub(r"[^A-Za-z0-9\-]", "_", scope_part)
    ts = requested_at.strftime("%Y%m%dT%H%M%SZ")
    return f"{framework_key}_{scope_part}_{ts}.{extension}"
