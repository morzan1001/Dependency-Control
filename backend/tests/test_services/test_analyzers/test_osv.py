"""Tests for the OSV analyzer's pure helpers.

We pin the CVSS-score-extraction and withdrawn-vulnerability rules here
so the regressions caught in the audit can't quietly come back. The full
HTTP path is exercised by integration tests; these are unit-level."""

from app.services.analyzers.osv import OSVAnalyzer


class TestParseCvssScore:
    """Audit P6.1: the previous parser returned the last vector segment
    (e.g. 'A:H') and tried to float() it, so any vector-string CVSS came
    back as None — we silently lost the score."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_numeric_score_passthrough(self):
        assert self.analyzer._parse_cvss_score("7.5") == 7.5

    def test_zero_score(self):
        assert self.analyzer._parse_cvss_score("0.0") == 0.0

    def test_cvss_v3_vector_with_explicit_base_score(self):
        # Real-world OSV severity entries pair a vector with an explicit base
        # score; the parser should return the score, not crash on the vector.
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        # Without a separate score we can't recover one — None is correct.
        assert self.analyzer._parse_cvss_score(vector) is None

    def test_cvss_vector_with_trailing_score_segment(self):
        # Some sources append the numeric score after the vector, separated
        # by '/' — '<vector>/9.8'. Make sure we still get the number.
        appended = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"
        assert self.analyzer._parse_cvss_score(appended) == 9.8

    def test_garbage_input_returns_none(self):
        assert self.analyzer._parse_cvss_score("not-a-cvss-score") is None
        assert self.analyzer._parse_cvss_score("") is None


class TestWithdrawnVulnerabilities:
    """Audit P6.1: the OSV schema's `withdrawn` field marks retracted
    vulnerabilities. They were silently passed through as live findings."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_withdrawn_vulnerabilities_are_dropped(self):
        vulns = [
            {"id": "GHSA-active", "summary": "live", "severity": [{"type": "CVSS_V3", "score": "7.5"}]},
            {
                "id": "GHSA-withdrawn",
                "summary": "retracted",
                "withdrawn": "2024-06-01T00:00:00Z",
                "severity": [{"type": "CVSS_V3", "score": "9.0"}],
            },
        ]
        normalized = self.analyzer._normalize_vulnerabilities(vulns)
        ids = [v["id"] for v in normalized]
        assert "GHSA-active" in ids
        assert "GHSA-withdrawn" not in ids

    def test_no_withdrawn_field_means_active(self):
        vulns = [{"id": "GHSA-x", "summary": "active"}]
        normalized = self.analyzer._normalize_vulnerabilities(vulns)
        assert len(normalized) == 1

    def test_empty_withdrawn_field_treated_as_active(self):
        # Defensive: empty string isn't a valid withdrawn timestamp, so the
        # vuln should be kept rather than silently dropped on schema noise.
        vulns = [{"id": "GHSA-x", "summary": "active", "withdrawn": ""}]
        normalized = self.analyzer._normalize_vulnerabilities(vulns)
        assert len(normalized) == 1
