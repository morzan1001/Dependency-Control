"""An alert nobody re-reads must carry its own truncation notice."""

from app.schemas.notification import AlertVulnerability
from app.services.notifications.mattermost_formatter import (
    build_advisory_props,
    build_analysis_completed_props,
    build_generic_props,
    build_vulnerability_found_props,
)
from app.services.notifications.slack_formatter import (
    _MAX_BLOCKS,
    _SECTION_TEXT_MAX_LENGTH,
    AFFECTED_PROJECTS_SHOWN,
    PROJECT_FINDINGS_SHOWN,
    build_advisory_blocks,
    build_analysis_completed_blocks,
    build_generic_blocks,
    build_vulnerability_found_blocks,
)

_SCAN_LINK = "https://dc.example.com/scans/s1"
_DASHBOARD_LINK = "https://dc.example.com"
_LISTED_VULNS = 10
_PRIORITY_FOUND = 431
_AFFECTED_PROJECTS = 132
_FINDINGS_PER_PROJECT = 9


_PHISHING_PACKAGE = "<https://evil.example/fix|Apply the fix>"
_MD_PHISHING_PACKAGE = "[Apply the fix](https://evil.example/fix)"


def _vulns(count: int) -> list[AlertVulnerability]:
    return [
        AlertVulnerability(id=f"CVE-2024-{index:04d}", severity="CRITICAL", package="openssl", version="3.0.0")
        for index in range(count)
    ]


def _slack_alert(top_vulns: list[AlertVulnerability], critical_count: int = 1) -> list[dict]:
    return build_vulnerability_found_blocks(
        project_name="demo",
        kev_count=3,
        high_epss_count=4,
        priority_count=_PRIORITY_FOUND,
        critical_count=critical_count,
        top_vulns=top_vulns,
        scan_link=_SCAN_LINK,
    )


def _mattermost_alert(top_vulns: list[AlertVulnerability], critical_count: int = 1) -> dict:
    return build_vulnerability_found_props(
        project_name="demo",
        kev_count=3,
        high_epss_count=4,
        priority_count=_PRIORITY_FOUND,
        critical_count=critical_count,
        top_vulns=top_vulns,
        scan_link=_SCAN_LINK,
    )


def _projects(count: int) -> list[dict[str, object]]:
    return [
        {"name": f"project-{index:03d}", "findings": [f"CVE-2024-{n:04d}" for n in range(_FINDINGS_PER_PROJECT)]}
        for index in range(count)
    ]


def _section_texts(blocks: list[dict]) -> list[str]:
    return [b["text"]["text"] for b in blocks if b.get("type") == "section" and "text" in b]


class TestSlackVulnerabilityAlert:
    def _blocks(self) -> list[dict]:
        return _slack_alert(_vulns(_LISTED_VULNS))

    def test_the_vulnerability_list_names_the_population_it_was_drawn_from(self):
        assert any(f"({_LISTED_VULNS} of {_PRIORITY_FOUND})" in text for text in _section_texts(self._blocks()))

    def test_every_vulnerability_the_caller_passed_is_listed(self):
        listed = "\n".join(_section_texts(self._blocks()))

        for vuln in _vulns(_LISTED_VULNS):
            assert vuln.id in listed

    def test_the_counts_say_what_they_count(self):
        fields = next(b["fields"] for b in self._blocks() if "fields" in b)
        texts = " ".join(f["text"] for f in fields)
        assert "High EPSS (EPSS >= 10%)" in texts
        assert f"Priority (Critical/High/KEV/High EPSS):* {_PRIORITY_FOUND}" in texts

    def test_a_line_names_version_and_tags(self):
        vuln = AlertVulnerability(
            id="CVE-1", severity="HIGH", package="log4j", version="2.14", in_kev=True, epss_score=0.5
        )

        listed = "\n".join(_section_texts(_slack_alert([vuln])))

        assert "\n1. `CVE-1` \U0001f7e0 HIGH \u2014 log4j@2.14  _[KEV, EPSS: 50.0%]_" in listed

    def test_an_sbom_component_name_is_not_read_as_a_slack_link(self):
        vuln = AlertVulnerability(id="CVE-1", severity="HIGH", package=_PHISHING_PACKAGE, version="<1>")

        listed = "\n".join(_section_texts(_slack_alert([vuln])))

        assert "&lt;https://evil.example/fix|Apply the fix&gt;@&lt;1&gt;" in listed

    def test_an_alert_without_criticals_does_not_claim_them(self):
        lead = _section_texts(_slack_alert(_vulns(1), critical_count=0))[0]

        assert lead == "Security scan detected high-priority vulnerabilities in *demo*."


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

        assert any(f"({AFFECTED_PROJECTS_SHOWN} of {_AFFECTED_PROJECTS})" in text for text in texts)

    def test_a_project_with_more_findings_than_fit_still_counts_the_rest(self):
        texts = "\n".join(_section_texts(self._blocks()))

        assert f"+{_FINDINGS_PER_PROJECT - PROJECT_FINDINGS_SHOWN} more" in texts

    def test_a_version_range_in_the_message_is_not_read_as_a_slack_link(self):
        blocks = build_advisory_blocks(subject="s", message="affected: <2.17.1 & >=2.0")

        assert "affected: &lt;2.17.1 &amp; &gt;=2.0" in _section_texts(blocks)

    def test_a_project_name_is_not_read_as_a_slack_mention(self):
        blocks = build_advisory_blocks(
            subject="s", message="m", affected_projects=[{"name": "<!channel>", "findings": ["a (<1)"]}]
        )

        assert "*&lt;!channel&gt;*: a (&lt;1)" in "\n".join(_section_texts(blocks))


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

    def test_an_error_text_is_not_read_as_a_slack_link(self):
        blocks = build_generic_blocks("Scan failed", "upstream said <html> & gave up")

        assert _section_texts(blocks) == ["upstream said &lt;html&gt; &amp; gave up"]


class TestSlackAnalysisCompleted:
    def test_names_and_analyzer_results_are_escaped(self):
        blocks = build_analysis_completed_blocks(
            project_name="<!channel>",
            scan_id="s1",
            total_findings=0,
            severity_counts={},
            results_summary=["osv: Failed (<timeout>)"],
            analyzer_count=1,
            scan_link=_SCAN_LINK,
        )
        texts = "\n".join(_section_texts(blocks))

        assert "*&lt;!channel&gt;*" in texts
        assert "osv: Failed (&lt;timeout&gt;)" in texts


class TestSlackAdvisoryBody:
    def test_a_long_announcement_arrives_whole_across_sections(self):
        blocks = build_advisory_blocks(
            subject="advisory", message="y" * (_SECTION_TEXT_MAX_LENGTH * 2), dashboard_link=_DASHBOARD_LINK
        )

        assert _section_texts(blocks) == ["y" * _SECTION_TEXT_MAX_LENGTH] * 2

    def test_an_announcement_too_long_for_slack_ends_by_saying_how_much_is_missing(self):
        blocks = build_advisory_blocks(
            subject="advisory",
            message="y" * (_SECTION_TEXT_MAX_LENGTH * _MAX_BLOCKS),
            affected_projects=_projects(1),
            dashboard_link=_DASHBOARD_LINK,
        )
        texts = _section_texts(blocks)

        assert len(blocks) == _MAX_BLOCKS
        assert "more characters did not fit in this message" in texts[-2]
        assert texts[-1].startswith("*Your Projects Using the Package")


class TestMattermostAlerts:
    def test_the_vulnerability_list_names_the_population_it_was_drawn_from(self):
        props = _mattermost_alert(_vulns(_LISTED_VULNS))

        assert f"({_LISTED_VULNS} of {_PRIORITY_FOUND})" in props["attachments"][0]["text"]

    def test_a_line_names_version_and_tags(self):
        vuln = AlertVulnerability(
            id="CVE-1", severity="HIGH", package="log4j", version="2.14", in_kev=True, epss_score=0.5
        )

        text = _mattermost_alert([vuln])["attachments"][0]["text"]

        assert "1. `CVE-1` \U0001f7e0 HIGH \u2014 log4j@2.14  *[KEV, EPSS: 50.0%]*" in text

    def test_an_sbom_component_name_is_not_rendered_as_a_link(self):
        vuln = AlertVulnerability(id="CVE-`1`", severity="HIGH", package=_MD_PHISHING_PACKAGE, version="1_0")

        text = _mattermost_alert([vuln])["attachments"][0]["text"]

        assert "`CVE-1`" in text
        assert "\\[Apply the fix\\]\\(https://evil.example/fix\\)@1\\_0" in text

    def test_an_alert_without_criticals_does_not_claim_them(self):
        text = _mattermost_alert(_vulns(1), critical_count=0)["attachments"][0]["text"]

        assert text.startswith("Security scan detected high-priority vulnerabilities in **demo**.")

    def test_the_counts_say_what_they_count(self):
        props = _mattermost_alert(_vulns(_LISTED_VULNS))
        titles = [field["title"] for field in props["attachments"][0]["fields"]]
        assert any(title.endswith("High EPSS (EPSS >= 10%)") for title in titles)
        assert any(title.endswith("Priority (Critical/High/KEV/High EPSS)") for title in titles)

    def test_the_project_list_names_the_population_it_was_drawn_from(self):
        props = build_advisory_props(
            subject="log4shell",
            message="rotate now",
            affected_projects=_projects(_AFFECTED_PROJECTS),
            dashboard_link=_DASHBOARD_LINK,
        )

        assert f"({AFFECTED_PROJECTS_SHOWN} of {_AFFECTED_PROJECTS})" in props["attachments"][0]["text"]

    def test_project_names_and_findings_are_not_rendered_as_markdown(self):
        props = build_advisory_props(
            subject="s", message="m", affected_projects=[{"name": "![x](https://t.example/p)", "findings": ["a_b"]}]
        )

        assert "- **\\!\\[x\\]\\(https://t.example/p\\)**: a\\_b" in props["attachments"][0]["text"]

    def test_a_generic_message_is_not_rendered_as_markdown(self):
        props = build_generic_props("Scan failed", "upstream said [click](https://evil.example)")

        assert props["attachments"][0]["text"] == "upstream said \\[click\\]\\(https://evil.example\\)"

    def test_names_and_analyzer_results_are_escaped(self):
        props = build_analysis_completed_props(
            project_name="*demo*",
            scan_id="s1",
            total_findings=0,
            severity_counts={},
            results_summary=["osv: Failed (see [log](https://x))"],
            analyzer_count=1,
            scan_link=_SCAN_LINK,
        )
        text = props["attachments"][0]["text"]

        assert "**\\*demo\\***" in text
        assert "osv: Failed \\(see \\[log\\]\\(https://x\\)\\)" in text


def _completed_colour(**severity_counts: int) -> str:
    props = build_analysis_completed_props(
        project_name="demo",
        scan_id="s1",
        total_findings=sum(severity_counts.values()),
        severity_counts=severity_counts,
        results_summary=[],
        analyzer_count=0,
        scan_link=_SCAN_LINK,
    )
    return props["attachments"][0]["color"]


class TestMattermostSeverityColour:
    def test_a_scan_with_highs_is_not_coloured_like_a_clean_one(self):
        assert _completed_colour(HIGH=3) != _completed_colour()

    def test_each_severity_tier_is_coloured_apart_from_the_others(self):
        tiers = {_completed_colour(CRITICAL=1, HIGH=3), _completed_colour(HIGH=3), _completed_colour()}

        assert len(tiers) == 3
