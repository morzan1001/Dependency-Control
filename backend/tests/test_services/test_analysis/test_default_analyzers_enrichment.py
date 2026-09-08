"""A default installation must reach the EPSS/KEV enrichment service.

_run_epss_kev_enrichment is its only caller and is gated on the active analyzer set, so a default
set without epss_kev leaves in_kev, epss_score and the enrichment risk_score unwritten on every
scan — and the KEV tab, the prioritized counts and the three incident cards read the resulting
zeros as "no actively exploited vulnerabilities".
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.constants import DEFAULT_ACTIVE_ANALYZERS
from app.models.project import Project
from app.models.system import SystemSettings
from app.schemas.project import ProjectCreate
from app.schemas.system import SystemSettingsBase
from app.services.analysis.engine import _run_vuln_enrichments

_SCAN_ID = "scan-1"
_FINDINGS = [{"finding_id": "log4j-core:2.14.1", "details": {"vulnerabilities": [{"id": "CVE-2021-44228"}]}}]


def _run(monkeypatch, active_analyzers):
    enrich = AsyncMock()
    monkeypatch.setattr("app.services.analysis.engine.enrich_vulnerability_findings", enrich)
    result_repo = SimpleNamespace(create_raw=AsyncMock())
    summary: list[str] = []

    asyncio.run(
        _run_vuln_enrichments(
            list(active_analyzers),
            _FINDINGS,
            _SCAN_ID,
            None,
            None,
            None,
            result_repo,
            None,
            None,
            None,
            summary,
        )
    )
    return enrich, result_repo, summary


def test_default_analyzer_set_runs_the_enrichment(monkeypatch):
    enrich, result_repo, summary = _run(monkeypatch, DEFAULT_ACTIVE_ANALYZERS)
    enrich.assert_awaited_once()
    assert result_repo.create_raw.await_args.args[0]["analyzer_name"] == "epss_kev"
    assert summary == ["epss_kev: Success (1 enriched)"]


def test_a_set_without_the_enrichment_writes_nothing(monkeypatch):
    without = [a for a in DEFAULT_ACTIVE_ANALYZERS if a != "epss_kev"]
    enrich, result_repo, summary = _run(monkeypatch, without)
    enrich.assert_not_awaited()
    result_repo.create_raw.assert_not_awaited()
    assert summary == []


@pytest.mark.parametrize(
    "defaults",
    [
        Project(name="p").active_analyzers,
        SystemSettings().default_active_analyzers,
        SystemSettingsBase().default_active_analyzers,
        ProjectCreate(name="p").active_analyzers,
    ],
)
def test_every_default_carrier_agrees(defaults):
    assert defaults == list(DEFAULT_ACTIVE_ANALYZERS)
