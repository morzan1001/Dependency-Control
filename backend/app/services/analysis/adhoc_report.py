"""HTML rendering of an ad-hoc analysis result."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from app.core.constants import sort_by_severity
from app.schemas.adhoc import AdhocAnalyzeResponse

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TEMPLATE_NAME = "adhoc_report.html"

# Unconditional rather than derived from the template's suffix: every string in this report
# comes out of a posted SBOM, so renaming the file must not be able to turn escaping off.
_ENV = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)

# Rows shown in the findings table; the JSON response carries the full set.
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


def render_adhoc_html(result: AdhocAnalyzeResponse) -> str:
    """Render the result as a standalone HTML document.

    The stylesheet is inlined: an HTTP response has no base URL, so a linked file would 404.
    """
    rows = sort_by_severity([_row(finding) for finding in result.findings])

    return _ENV.get_template(_TEMPLATE_NAME).render(
        generated_at=datetime.now(timezone.utc).isoformat(),
        stats=result.stats,
        findings=rows[:_FINDING_ROW_CAP],
        findings_total=len(result.findings),
        findings_shown=min(len(rows), _FINDING_ROW_CAP),
        dependencies_total=len(result.dependencies),
        recommendations=result.recommendations[:_RECOMMENDATION_ROW_CAP],
        analyzers=result.analyzers,
        epss_kev_summary=result.epss_kev_summary,
        reachability_summary=result.reachability_summary,
        waivers_applied=result.waivers_applied,
        waived_count=result.waived_count,
        truncated=result.truncated,
    )
