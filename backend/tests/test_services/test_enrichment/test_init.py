"""Tests for the enrichment package facade (services/enrichment/__init__.py)."""

from unittest.mock import AsyncMock

import pytest

from app.services import enrichment
from app.services.enrichment import enrich_vulnerability_findings


@pytest.mark.asyncio
async def test_enrich_vulnerability_findings_does_not_close_shared_singleton(monkeypatch):
    """The enrichment service is a process-lifetime singleton shared by concurrent
    scan runs and request-time analytics. A completed run must NOT close the shared
    HTTP client, or concurrent in-flight runs hit "client has been closed" and lose
    their EPSS/KEV data (audit bug/high #1)."""
    enrich_mock = AsyncMock()
    close_mock = AsyncMock()
    monkeypatch.setattr(enrichment.vulnerability_enrichment_service, "enrich_findings", enrich_mock)
    monkeypatch.setattr(enrichment.vulnerability_enrichment_service, "close", close_mock)

    findings: list = [{"details": {"vulnerabilities": []}}]
    await enrich_vulnerability_findings(findings)

    enrich_mock.assert_awaited_once_with(findings)
    close_mock.assert_not_called()
