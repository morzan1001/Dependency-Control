"""Unit tests for TeamsFormatter Adaptive Card builders."""

import pytest

from app.services.webhooks.teams_formatter import TeamsFormatter


def _get_card(result: dict) -> dict:
    """Extract the Adaptive Card content from the Teams message envelope."""
    return result["attachments"][0]["content"]


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

    def test_card_has_summary(self):
        card = _get_card(TeamsFormatter.build_test_card())
        assert "summary" in card


class TestBuildTestCard:
    def test_accent_container_style(self):
        card = _get_card(TeamsFormatter.build_test_card())
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "accent"

    def test_has_confirmation_text(self):
        card = _get_card(TeamsFormatter.build_test_card())
        container = next(b for b in card["body"] if b["type"] == "Container")
        texts = [item["text"] for item in container["items"] if item["type"] == "TextBlock"]
        assert any("configured correctly" in t for t in texts)


class TestBuildGenericCard:
    def test_subject_as_header(self):
        card = _get_card(TeamsFormatter.build_generic_card("Test Alert", "Something happened"))
        header = next(b for b in card["body"] if b["type"] == "TextBlock")
        assert header["text"] == "Test Alert"
        assert header["weight"] == "Bolder"

    def test_no_action_when_no_url(self):
        card = _get_card(TeamsFormatter.build_generic_card("Test", "Message"))
        assert "actions" not in card or card.get("actions") == [] or card.get("actions") is None

    def test_action_button_when_url_given(self):
        card = _get_card(TeamsFormatter.build_generic_card("Test", "Message", url="https://example.com"))
        action = card["actions"][0]
        assert action["type"] == "Action.OpenUrl"
        assert action["url"] == "https://example.com"


class TestBuildScanCompletedCard:
    def test_good_style_when_no_findings(self):
        card = _get_card(TeamsFormatter.build_scan_completed_card(
            project_name="MyApp",
            _scan_id="scan-1",
            findings={"total": 0, "stats": {}},
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "good"

    def test_warning_style_when_only_non_critical_findings(self):
        card = _get_card(TeamsFormatter.build_scan_completed_card(
            project_name="MyApp",
            _scan_id="scan-1",
            findings={"total": 5, "stats": {"high": 5}},
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "warning"

    def test_attention_style_when_critical_findings(self):
        card = _get_card(TeamsFormatter.build_scan_completed_card(
            project_name="MyApp",
            _scan_id="scan-1",
            findings={"total": 3, "stats": {"critical": 2, "high": 1}},
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "attention"

    def test_factset_contains_project_and_total(self):
        card = _get_card(TeamsFormatter.build_scan_completed_card(
            project_name="MyApp",
            _scan_id="scan-1",
            findings={"total": 3, "stats": {}},
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        assert "Project" in titles
        assert "Total Findings" in titles

    def test_view_button_when_url_given(self):
        card = _get_card(TeamsFormatter.build_scan_completed_card(
            project_name="MyApp",
            _scan_id="scan-1",
            findings={"total": 0, "stats": {}},
            scan_url="https://app.example.com/scans/1",
        ))
        assert card["actions"][0]["type"] == "Action.OpenUrl"
        assert card["actions"][0]["url"] == "https://app.example.com/scans/1"

    def test_no_actions_when_no_url(self):
        card = _get_card(TeamsFormatter.build_scan_completed_card(
            project_name="MyApp",
            _scan_id="scan-1",
            findings={"total": 0, "stats": {}},
        ))
        assert "actions" not in card


class TestBuildVulnerabilityFoundCard:
    def test_attention_style_when_critical(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 2, "high": 1, "kev": 0, "high_epss": 0, "top": []},
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "attention"

    def test_warning_style_when_only_high(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 0, "high": 3, "kev": 0, "high_epss": 0, "top": []},
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "warning"

    def test_factset_shows_critical_and_high(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 2, "high": 5, "kev": 0, "high_epss": 0, "top": []},
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        assert "Critical" in titles
        assert "High" in titles

    def test_kev_shown_when_nonzero(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 1, "high": 0, "kev": 2, "high_epss": 0, "top": []},
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        assert "Known Exploited (KEV)" in titles

    def test_kev_omitted_when_zero(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 1, "high": 0, "kev": 0, "high_epss": 0, "top": []},
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        assert "Known Exploited (KEV)" not in titles

    def test_top_vulns_shown_max_three(self):
        top = [
            {"cve_id": f"CVE-2024-{i}", "severity": "Critical", "component": "lib"}
            for i in range(5)
        ]
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 5, "high": 0, "kev": 0, "high_epss": 0, "top": top},
        ))
        containers = [b for b in card["body"] if b["type"] == "Container"]
        cve_blocks = []
        for container in containers:
            for item in container.get("items", []):
                if item.get("type") == "TextBlock" and "CVE-2024-" in item.get("text", ""):
                    cve_blocks.append(item)
        assert len(cve_blocks) == 3

    def test_high_epss_shown_when_nonzero(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 0, "high": 1, "kev": 0, "high_epss": 3, "top": []},
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        assert "High EPSS" in titles

    def test_high_epss_omitted_when_zero(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 1, "high": 0, "kev": 0, "high_epss": 0, "top": []},
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        assert "High EPSS" not in titles

    def test_title_is_high_when_only_high_findings(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 0, "high": 3, "kev": 0, "high_epss": 0, "top": []},
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        header = next(i for i in container["items"] if i["type"] == "TextBlock")
        assert "High" in header["text"]
        assert "Critical" not in header["text"]

    def test_no_actions_when_no_url(self):
        card = _get_card(TeamsFormatter.build_vulnerability_found_card(
            project_name="MyApp",
            _scan_id="scan-1",
            vulns={"critical": 1, "high": 0, "kev": 0, "high_epss": 0, "top": []},
        ))
        assert "actions" not in card


class TestBuildAnalysisFailedCard:
    def test_attention_style(self):
        card = _get_card(TeamsFormatter.build_analysis_failed_card(
            project_name="MyApp",
            error="Timeout during SBOM analysis",
        ))
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "attention"

    def test_factset_shows_project_and_error(self):
        card = _get_card(TeamsFormatter.build_analysis_failed_card(
            project_name="MyApp",
            error="Timeout during SBOM analysis",
        ))
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = [f["title"] for f in factset["facts"]]
        values = [f["value"] for f in factset["facts"]]
        assert "Project" in titles
        assert "Error" in titles
        assert "Timeout during SBOM analysis" in values
