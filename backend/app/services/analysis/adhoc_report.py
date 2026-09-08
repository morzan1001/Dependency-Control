"""HTML rendering of an ad-hoc analysis result."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.core.constants import sort_by_severity
from app.schemas.adhoc import AdhocAnalyzeResponse

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TEMPLATE_NAME = "adhoc_report.html"

# Unconditional rather than derived from the template's suffix: every string in this report
# comes out of a posted SBOM, so renaming the file must not be able to turn escaping off.
# StrictUndefined binds the template to the context: a name the context does not carry raises
# instead of rendering an empty section that reads as "nothing to report".
_ENV = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True, undefined=StrictUndefined)

# Response fields the report presents through a derived value rather than directly; every other
# field reaches the template under its own name, so the schema cannot gain or lose one silently.
_DERIVED_FIELDS = frozenset({"findings", "dependencies", "recommendations"})

# Rows shown in the tables; the JSON response carries the full set, and each heading
# names how many of the total it is showing.
_FINDING_ROW_CAP = 500
_RECOMMENDATION_ROW_CAP = 50
_DESCRIPTION_CHARS = 300
_UNKNOWN_SEVERITY = "UNKNOWN"


def _row(finding: dict[str, Any]) -> dict[str, str | bool]:
    return {
        "type": str(finding.get("type", "")),
        "severity": str(finding.get("severity") or _UNKNOWN_SEVERITY),
        "component": str(finding.get("component", "")),
        "version": str(finding.get("version") or ""),
        "description": str(finding.get("description") or "")[:_DESCRIPTION_CHARS],
        "scanners": ", ".join(str(scanner) for scanner in (finding.get("scanners") or [])),
        "waived": bool(finding.get("waived")),
    }


def report_context(result: AdhocAnalyzeResponse) -> dict[str, Any]:
    """The template's whole world, read off the response schema rather than hand-listed."""
    rows = sort_by_severity([_row(finding) for finding in result.findings])
    context: dict[str, Any] = {
        name: getattr(result, name) for name in AdhocAnalyzeResponse.model_fields if name not in _DERIVED_FIELDS
    }
    context.update(
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=rows[:_FINDING_ROW_CAP],
        findings_total=len(result.findings),
        findings_shown=min(len(rows), _FINDING_ROW_CAP),
        dependencies_total=len(result.dependencies),
        recommendations=result.recommendations[:_RECOMMENDATION_ROW_CAP],
        recommendations_total=len(result.recommendations),
        recommendations_shown=min(len(result.recommendations), _RECOMMENDATION_ROW_CAP),
    )
    return context


def render_adhoc_html(result: AdhocAnalyzeResponse) -> str:
    """Render the result as a standalone HTML document.

    The stylesheet is inlined: an HTTP response has no base URL, so a linked file would 404.
    """
    return _ENV.get_template(_TEMPLATE_NAME).render(**report_context(result))
