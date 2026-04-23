"""Renderer protocol — each format implements render(eval, report) → bytes."""

from typing import Optional, Protocol, Tuple

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import FrameworkEvaluation, ReportFormat


class Renderer(Protocol):
    format: ReportFormat
    mime_type: str
    extension: str

    def render(
        self,
        evaluation: FrameworkEvaluation,
        report: ComplianceReport,
        *,
        disclaimer: Optional[str] = None,
    ) -> Tuple[bytes, str, str]:
        """Return (artifact_bytes, filename, mime_type)."""
        ...


def build_filename(
    framework_key: str, scope: str, scope_id: Optional[str],
    requested_at, extension: str,
) -> str:
    """Construct a descriptive, filesystem-safe filename.

    Example: "nist-sp-800-131a_project-p1_20260420T100000Z.pdf"
    """
    scope_part = f"{scope}" + (f"-{scope_id}" if scope_id else "")
    import re
    scope_part = re.sub(r"[^A-Za-z0-9\-]", "_", scope_part)
    ts = requested_at.strftime("%Y%m%dT%H%M%SZ")
    return f"{framework_key}_{scope_part}_{ts}.{extension}"
