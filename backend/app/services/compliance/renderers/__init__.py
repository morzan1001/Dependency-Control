"""Compliance report renderers.

`RENDERER_REGISTRY` maps each `ReportFormat` to its renderer instance.
"""

from app.schemas.compliance import ReportFormat
from app.services.compliance.renderers.base import Renderer
from app.services.compliance.renderers.csv_renderer import CsvRenderer
from app.services.compliance.renderers.json_renderer import JsonRenderer
from app.services.compliance.renderers.pdf_renderer import PdfRenderer
from app.services.compliance.renderers.sarif_renderer import SarifRenderer

RENDERER_REGISTRY: "dict[ReportFormat, Renderer]" = {
    ReportFormat.PDF: PdfRenderer(),
    ReportFormat.CSV: CsvRenderer(),
    ReportFormat.JSON: JsonRenderer(),
    ReportFormat.SARIF: SarifRenderer(),
}

__all__ = ["RENDERER_REGISTRY", "Renderer"]
