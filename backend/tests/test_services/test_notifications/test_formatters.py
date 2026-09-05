"""An alert nobody re-reads must carry its own truncation notice."""

from app.services.notifications.mattermost_formatter import (
    build_advisory_props,
    build_vulnerability_found_props,
)
from app.services.notifications.slack_formatter import (
    _AFFECTED_PROJECTS_SHOWN,
    _CUT_MARKER,
    _MAX_BLOCKS,
    _PROJECT_FINDINGS_SHOWN,
    _SECTION_TEXT_MAX_LENGTH,
    build_advisory_blocks,
    build_generic_blocks,
    build_vulnerability_found_blocks,
)

_SCAN_LINK = "https://dc.example.com/scans/s1"
_DASHBOARD_LINK = "https://dc.example.com"
_LISTED_VULNS = 10
_CRITICAL_FOUND = 431
_AFFECTED_PROJECTS = 132
_FINDINGS_PER_PROJECT = 9


def _vulns(count: int) -> list[dict[str, object]]:
    return [
        {"id": f"CVE-2024-{index:04d}", "severity": "CRITICAL", "package": "openssl", "version": "3.0.0"}
        for index in range(count)
    ]


def _projects(count: int) -> list[dict[str, object]]:
    return [
        {"name": f"project-{index:03d}", "findings": [f"CVE-2024-{n:04d}" for n in range(_FINDINGS_PER_PROJECT)]}
        for index in range(count)
    ]


def _section_texts(blocks: list[dict]) -> list[str]:
    return [b["text"]["text"] for b in blocks if b.get("type") == "section" and "text" in b]


class TestSlackVulnerabilityAlert:
    def _blocks(self) -> list[dict]:
        return build_vulnerability_found_blocks(
            project_name="demo",
            kev_count=3,
            high_epss_count=4,
            critical_count=_CRITICAL_FOUND,
            top_vulns=_vulns(_LISTED_VULNS),
            scan_link=_SCAN_LINK,
        )

    def test_the_vulnerability_list_names_the_population_it_was_drawn_from(self):
        assert any(f"({_LISTED_VULNS} of {_CRITICAL_FOUND})" in text for text in _section_texts(self._blocks()))

    def test_every_vulnerability_the_caller_passed_is_listed(self):
        listed = "\n".join(_section_texts(self._blocks()))

        for vuln in _vulns(_LISTED_VULNS):
            assert vuln["id"] in listed


class TestSlackAdvisory:
    def _blocks(self) -> list[dict]:
        return build_advisory_blocks(
            subject="log4shell",
            message="rotate now",
            affected_projects=_projects(_AFFECTED_PROJECTS),
            dashboard_link=_DASHBOARD_LINK,
        )

    def test_the_project_list_names_the_population_it_was_drawn_from(self):
        texts = _section_texts(self._blocks())

        assert any(f"({_AFFECTED_PROJECTS_SHOWN} of {_AFFECTED_PROJECTS})" in text for text in texts)

    def test_a_project_with_more_findings_than_fit_still_counts_the_rest(self):
        texts = "\n".join(_section_texts(self._blocks()))

        assert f"+{_FINDINGS_PER_PROJECT - _PROJECT_FINDINGS_SHOWN} more" in texts


class TestSlackGenericMessage:
    def _long_message(self) -> str:
        return "x" * (_SECTION_TEXT_MAX_LENGTH * _MAX_BLOCKS)

    def test_a_message_too_long_for_slack_ends_by_saying_how_much_is_missing(self):
        blocks = build_generic_blocks("subject", self._long_message())

        assert len(blocks) <= _MAX_BLOCKS
        assert "did not fit in this message" in _section_texts(blocks)[-1]

    def test_a_message_that_fits_carries_no_notice(self):
        blocks = build_generic_blocks("subject", "short enough")

        assert "did not fit" not in "\n".join(_section_texts(blocks))


class TestSlackSectionBudget:
    def test_a_section_over_slacks_budget_is_marked_rather_than_silently_clipped(self):
        blocks = build_advisory_blocks(
            subject="advisory",
            message="y" * (_SECTION_TEXT_MAX_LENGTH * 2),
            dashboard_link=_DASHBOARD_LINK,
        )
        body = _section_texts(blocks)[0]

        assert len(body) == _SECTION_TEXT_MAX_LENGTH
        assert body.endswith(_CUT_MARKER)


class TestMattermostAlerts:
    def test_the_vulnerability_list_names_the_population_it_was_drawn_from(self):
        props = build_vulnerability_found_props(
            project_name="demo",
            kev_count=3,
            high_epss_count=4,
            critical_count=_CRITICAL_FOUND,
            top_vulns=_vulns(_LISTED_VULNS),
            scan_link=_SCAN_LINK,
        )

        assert f"({_LISTED_VULNS} of {_CRITICAL_FOUND})" in props["attachments"][0]["text"]

    def test_the_project_list_names_the_population_it_was_drawn_from(self):
        props = build_advisory_props(
            subject="log4shell",
            message="rotate now",
            affected_projects=_projects(_AFFECTED_PROJECTS),
            dashboard_link=_DASHBOARD_LINK,
        )

        assert f"({_AFFECTED_PROJECTS_SHOWN} of {_AFFECTED_PROJECTS})" in props["attachments"][0]["text"]
