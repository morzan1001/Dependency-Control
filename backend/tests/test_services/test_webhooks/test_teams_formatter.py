"""The Teams Adaptive Cards, built from what the webhook producers deliver."""

from unittest.mock import MagicMock

import pytest

from app.core.config import scan_link
from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
)
from app.models.stats import Stats
from app.services.analysis.notifications import _extract_vulnerability_info
from app.services.webhooks import webhook_service
from app.services.webhooks.teams_formatter import TeamsFormatter
from tests.helpers.webhooks import teams_card

_SCAN_LINK = scan_link("proj-1", "scan-1")


def _get_card(result: dict) -> dict:
    return result["attachments"][0]["content"]


def _entry(cve: str, severity: str = "CRITICAL", **details) -> dict:
    return _extract_vulnerability_info(
        {"id": cve, "severity": severity, **details},
        {"component": "requests", "version": "2.30.0"},
    ).model_dump()


def _header(card: dict) -> dict:
    return next(b for b in card["body"] if b["type"] == "Container")


def _title(card: dict) -> str:
    return _header(card)["items"][0]["text"]


def _facts(card: dict) -> dict[str, str]:
    factset = next(b for b in card["body"] if b["type"] == "FactSet")
    return {f["title"]: f["value"] for f in factset["facts"]}


def _texts(card: dict) -> list[str]:
    return [item["text"] for block in card["body"] for item in block.get("items", []) if "text" in item]


async def _scan_card(stats: Stats, total: int = 0, status: str = SCAN_STATUS_COMPLETED, failed=()) -> dict:
    return await teams_card(
        webhook_service.trigger_scan_completed(
            MagicMock(),
            "scan-1",
            "proj-1",
            "MyApp",
            total,
            stats.model_dump(),
            scan_status=status,
            failed_analyzers=list(failed),
        )
    )


async def _vuln_card(top: list[dict], critical=0, high=0, kev=0, high_epss=0, priority=None) -> dict:
    return await teams_card(
        webhook_service.trigger_vulnerability_found(
            MagicMock(),
            "scan-1",
            "proj-1",
            "MyApp",
            critical_count=critical,
            high_count=high,
            kev_count=kev,
            high_epss_count=high_epss,
            priority_count=len(top) if priority is None else priority,
            top_vulnerabilities=top,
        )
    )


class TestTeamsFormatterEnvelope:
    def test_outer_structure(self):
        result = TeamsFormatter.build_test_card()
        assert result["type"] == "message"
        assert len(result["attachments"]) == 1
        assert result["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
        assert result["attachments"][0]["contentUrl"] is None

    def test_adaptive_card_schema(self):
        card = _get_card(TeamsFormatter.build_test_card())
        assert card["type"] == "AdaptiveCard"
        assert card["version"] == "1.5"
        assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
        assert card["msteams"] == {"width": "Full"}
        assert card["summary"]


class TestBuildTestCard:
    def test_the_confirmation_sits_in_the_accent_header(self):
        card = _get_card(TeamsFormatter.build_test_card())
        assert _header(card)["style"] == "accent"
        assert any("configured correctly" in t for t in _texts(card))


class TestGenericCard:
    @pytest.mark.asyncio
    async def test_a_snake_case_event_is_titled_in_words(self):
        card = await teams_card(
            webhook_service.safe_trigger_webhooks(
                MagicMock(),
                WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
                {"scan_id": "scan-1", "project_id": "proj-1", "total": 3, "by_type": {"algorithm": 3}},
                "proj-1",
                context="cbom_ingest",
            )
        )

        assert (card["body"][0]["text"], card["summary"]) == ("Crypto Asset Ingested", "Crypto Asset Ingested")


class TestScanCompletedCard:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("stats", "style"),
        [
            (Stats(), "good"),
            (Stats(low=4, medium=2, info=9), "good"),
            (Stats(high=5), "warning"),
            (Stats(critical=2, high=1), "attention"),
        ],
    )
    async def test_the_header_is_as_alarming_as_the_most_severe_finding(self, stats, style):
        card = await _scan_card(stats, total=stats.critical + stats.high + stats.medium + stats.low + stats.info)

        assert _header(card)["style"] == style

    @pytest.mark.asyncio
    async def test_every_severity_count_gets_a_fact_in_severity_order(self):
        card = await _scan_card(Stats(unknown=1, negligible=2, high=1), total=4)

        assert list(_facts(card).items()) == [
            ("Project", "MyApp"),
            ("Total Findings", "4"),
            ("High", "1"),
            ("Negligible", "2"),
            ("Unknown", "1"),
        ]

    @pytest.mark.asyncio
    async def test_the_card_links_to_the_scan(self):
        card = await _scan_card(Stats())

        assert card["actions"] == [{"type": "Action.OpenUrl", "title": "View Scan Results", "url": _SCAN_LINK}]

    @pytest.mark.asyncio
    async def test_a_scan_whose_analyzers_failed_is_not_announced_as_all_clear(self):
        card = await _scan_card(Stats(), status=SCAN_STATUS_COMPLETED_WITH_ERRORS, failed=["trivy", "grype"])

        assert (_header(card)["style"], _title(card), _facts(card)["Failed Analyzers"]) == (
            "warning",
            "⚠️ Scan Completed with Errors",
            "trivy, grype",
        )

    @pytest.mark.asyncio
    async def test_criticals_stay_attention_when_the_scan_also_had_errors(self):
        card = await _scan_card(Stats(critical=1), total=1, status=SCAN_STATUS_COMPLETED_WITH_ERRORS, failed=["osv"])

        assert _header(card)["style"] == "attention"


class TestVulnerabilityFoundCard:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("counts", "style", "title"),
        [
            ({"critical": 2, "high": 1}, "attention", "🚨 Critical Vulnerabilities Found"),
            ({"high": 3}, "warning", "⚠️ High Vulnerabilities Found"),
            ({"kev": 1}, "warning", "⚠️ Known Exploited Vulnerability Found"),
            ({"high_epss": 1}, "warning", "⚠️ High-EPSS Vulnerability Found"),
        ],
    )
    async def test_the_title_names_what_raised_the_alert(self, counts, style, title):
        card = await _vuln_card([_entry("CVE-2024-1", "MEDIUM")], **counts)

        assert (_header(card)["style"], _title(card)) == (style, title)

    @pytest.mark.asyncio
    async def test_the_facts_count_each_trigger_that_fired(self):
        card = await _vuln_card([_entry("CVE-2024-1")], critical=1, high=5, kev=2)

        assert _facts(card) == {"Project": "MyApp", "Critical": "1", "High": "5", "Known Exploited (KEV)": "2"}

    @pytest.mark.asyncio
    async def test_high_epss_is_a_fact_when_it_fired(self):
        card = await _vuln_card([_entry("CVE-2024-1", "MEDIUM")], high_epss=3)

        assert _facts(card)["High EPSS"] == "3"

    @pytest.mark.asyncio
    async def test_every_listed_vulnerability_is_shown_under_the_population_it_came_from(self):
        top = [_entry(f"CVE-2024-{i}") for i in range(5)]

        texts = _texts(await _vuln_card(top, critical=5, priority=12))

        assert "**Top Priority Vulnerabilities (5 of 12)**" in texts
        assert [t for t in texts if "CVE-2024-" in t] == [
            f"{i + 1}. **CVE-2024-{i}** (CRITICAL) — requests@2.30.0" for i in range(5)
        ]

    @pytest.mark.asyncio
    async def test_a_line_carries_the_kev_and_epss_tags(self):
        top = [_entry("CVE-2021-44228", in_kev=True, epss_score=0.94)]

        texts = _texts(await _vuln_card(top, critical=1, kev=1, high_epss=1))

        assert "1. **CVE-2021-44228** (CRITICAL) — requests@2.30.0 [KEV] [EPSS: 94.0%]" in texts

    @pytest.mark.asyncio
    async def test_the_card_links_to_the_scan(self):
        card = await _vuln_card([_entry("CVE-2024-1")], critical=1)

        assert card["actions"] == [{"type": "Action.OpenUrl", "title": "View Vulnerabilities", "url": _SCAN_LINK}]


class TestAnalysisFailedCard:
    @pytest.mark.asyncio
    async def test_the_card_names_the_error_and_links_to_the_scan(self):
        card = await teams_card(
            webhook_service.trigger_analysis_failed(
                MagicMock(), "scan-1", "proj-1", "MyApp", "Timeout during SBOM analysis"
            )
        )

        assert _header(card)["style"] == "attention"
        assert _facts(card) == {"Project": "MyApp", "Error": "Timeout during SBOM analysis"}
        assert card["actions"] == [{"type": "Action.OpenUrl", "title": "View Details", "url": _SCAN_LINK}]
