from collections import defaultdict
from datetime import datetime, timezone
from itertools import chain, zip_longest
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.core.constants import get_severity_value
from app.core.cve import canonical_cves
from app.schemas.adhoc import AdhocAnalyzeResponse

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TEMPLATE_NAME = "adhoc_report.html"

# Posted-SBOM strings: escape unconditionally; StrictUndefined fails loudly instead of rendering an empty section.
_ENV = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True, undefined=StrictUndefined)

# Every other response field reaches the template under its own name, so the schema cannot drift silently.
_DERIVED_FIELDS = frozenset({"findings", "dependencies", "recommendations"})

# The JSON response carries the full set; each heading names how many of the total it shows.
_FINDING_ROW_CAP = 500
_RECOMMENDATION_ROW_CAP = 50
_DESCRIPTION_CHARS = 300


def _row(finding: dict[str, Any]) -> dict[str, str | bool]:
    return {
        "type": finding["type"],
        "severity": finding["severity"],
        "component": finding["component"],
        "version": finding["version"] or "",
        "description": finding["description"][:_DESCRIPTION_CHARS] or ", ".join(canonical_cves([finding["details"]])),
        "scanners": ", ".join(finding["scanners"]),
        "waived": finding["waived"],
    }


def _cap_order(rows: list[dict[str, str | bool]]) -> list[dict[str, str | bool]]:
    """Live findings first, most severe first; types alternate within a tier so none fills the row cap alone."""
    tiers: dict[tuple[bool, int], dict[str, list[dict[str, str | bool]]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        tiers[(bool(row["waived"]), -get_severity_value(str(row["severity"])))][str(row["type"])].append(row)
    return [
        row
        for tier in sorted(tiers)
        for row in chain.from_iterable(zip_longest(*tiers[tier].values()))
        if row is not None
    ]


def report_context(result: AdhocAnalyzeResponse) -> dict[str, Any]:
    rows = _cap_order([_row(finding) for finding in result.findings])
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
    """The stylesheet is inlined: an HTTP response has no base URL, so a linked file would 404."""
    return _ENV.get_template(_TEMPLATE_NAME).render(**report_context(result))
