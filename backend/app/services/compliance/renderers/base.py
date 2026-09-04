"""Renderer protocol — each format implements render(eval, report) → bytes."""

from datetime import datetime
from typing import Protocol

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import EvaluationCoverage, FrameworkEvaluation, ReportFormat

_COVERAGE_COMPLETE = "Evaluated all {in_scope} findings in scope."
_COVERAGE_PARTIAL = (
    "Evaluated {evaluated} of {in_scope} findings in scope, a cap of {limit} per report. "
    "Every verdict below was computed over that subset: a control reported as passed was not "
    "checked against the remaining {missing} findings and is not evidence of compliance. "
    "Narrow the scope and regenerate for a verdict that covers everything."
)


def coverage_statement(coverage: EvaluationCoverage | None) -> str | None:
    """The sentence a reader needs to know whether the verdicts cover the scope."""
    if coverage is None:
        return None
    if coverage.complete:
        return _COVERAGE_COMPLETE.format(in_scope=coverage.findings_in_scope)
    return _COVERAGE_PARTIAL.format(
        evaluated=coverage.findings_evaluated,
        in_scope=coverage.findings_in_scope,
        limit=coverage.limit,
        missing=coverage.findings_in_scope - coverage.findings_evaluated,
    )


class Renderer(Protocol):
    format: ReportFormat
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
