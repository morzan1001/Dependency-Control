"""Tests for SAST normalizers (OpenGrep, Bearer)."""

from app.services.aggregator import ResultAggregator


class TestNormalizeOpengrep:
    """Tests for normalize_opengrep - OpenGrep/Semgrep SAST normalization."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def _opengrep_result(self, findings):
        return {"results": findings}

    def test_basic_finding(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "rules.python.sql-injection",
                    "path": "app/views.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 42, "col": 60},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection detected",
                        "metadata": {},
                    },
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "sast"
        assert f.component == "app/views.py"
        assert "opengrep" in f.scanners

    def test_severity_mapping(self):
        """OpenGrep ERROR -> HIGH, WARNING -> MEDIUM, INFO -> LOW."""
        for og_sev, expected in [("ERROR", "HIGH"), ("WARNING", "MEDIUM"), ("INFO", "LOW")]:
            agg = ResultAggregator()
            result = self._opengrep_result(
                [
                    {
                        "check_id": "test-rule",
                        "path": "file.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 10},
                        "extra": {"severity": og_sev, "message": "test", "metadata": {}},
                    }
                ]
            )
            agg.aggregate("opengrep", result)
            f = list(agg.findings.values())[0]
            assert f.severity == expected, f"OpenGrep {og_sev} should map to {expected}"

    def test_cwe_ids_normalized(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "test-rule",
                    "path": "file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "test",
                        "metadata": {"cwe": ["CWE-79", "CWE-89"]},
                    },
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["cwe_ids"] == ["79", "89"]

    def test_owasp_metadata_captured(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "test-rule",
                    "path": "file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "test",
                        "metadata": {"owasp": ["A01:2021"]},
                    },
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["owasp"] == ["A01:2021"]

    def test_rule_name_in_description(self):
        """When check_id has dots, last part should prefix the description."""
        result = self._opengrep_result(
            [
                {
                    "check_id": "rules.python.sql-injection",
                    "path": "file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Raw query used",
                        "metadata": {},
                    },
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        f = list(self.agg.findings.values())[0]
        assert "sql-injection" in f.description
        assert "Raw query used" in f.description

    def test_findings_key_also_works(self):
        """OpenGrep can send data as 'findings' instead of 'results'."""
        result = {
            "findings": [
                {
                    "check_id": "rule",
                    "path": "file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {"severity": "INFO", "message": "test", "metadata": {}},
                }
            ]
        }
        self.agg.aggregate("opengrep", result)
        assert len(self.agg.findings) == 1

    def test_empty_results_skipped(self):
        self.agg.aggregate("opengrep", {"results": []})
        assert len(self.agg.findings) == 0

    def test_no_results_key_skipped(self):
        self.agg.aggregate("opengrep", {"other": "data"})
        assert len(self.agg.findings) == 0

    def test_location_captured(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "rule",
                    "path": "src/app.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 15, "col": 20},
                    "extra": {"severity": "ERROR", "message": "test", "metadata": {}},
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["start"] == {"line": 10, "column": 5}
        assert f.details["end"] == {"line": 15, "column": 20}


class TestNormalizeBearer:
    """Tests for normalize_bearer - Bearer SAST normalization."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_finding(self):
        result = {
            "findings": [
                {
                    "id": "python_lang_hardcoded_secret",
                    "title": "Hardcoded secret detected",
                    "severity": "critical",
                    "full_filename": "config.py",
                    "line_number": 25,
                }
            ]
        }
        self.agg.aggregate("bearer", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "sast"
        assert f.component == "config.py"
        assert "bearer" in f.scanners

    def test_severity_mapping(self):
        """Bearer uses lowercase severities that map to standard severities."""
        for bearer_sev, expected in [
            ("critical", "CRITICAL"),
            ("high", "HIGH"),
            ("medium", "MEDIUM"),
            ("low", "LOW"),
            ("warning", "LOW"),
            ("info", "INFO"),
        ]:
            agg = ResultAggregator()
            result = {
                "findings": [
                    {
                        "id": "rule",
                        "title": "test",
                        "severity": bearer_sev,
                        "full_filename": "file.py",
                        "line_number": 1,
                    }
                ]
            }
            agg.aggregate("bearer", result)
            f = list(agg.findings.values())[0]
            assert f.severity == expected, f"Bearer {bearer_sev} should map to {expected}"

    def test_grouped_by_severity_dict(self):
        """Bearer can group findings by severity key in a dict."""
        result = {
            "findings": {
                "high": [{"id": "rule1", "title": "High issue", "full_filename": "a.py", "line_number": 1}],
                "low": [{"id": "rule2", "title": "Low issue", "full_filename": "b.py", "line_number": 1}],
            }
        }
        self.agg.aggregate("bearer", result)
        assert len(self.agg.findings) == 2

    def test_severity_injected_from_group_key(self):
        """When findings are grouped by severity, items without 'severity' get it from the key."""
        result = {"findings": {"high": [{"id": "rule1", "title": "test", "full_filename": "a.py", "line_number": 1}]}}
        self.agg.aggregate("bearer", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "HIGH"

    def test_cwe_ids_normalized(self):
        result = {
            "findings": [
                {
                    "id": "rule",
                    "title": "test",
                    "severity": "high",
                    "full_filename": "file.py",
                    "line_number": 1,
                    "cwe_ids": ["CWE-79", "CWE-89"],
                }
            ]
        }
        self.agg.aggregate("bearer", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["cwe_ids"] == ["79", "89"]

    def test_filename_fallback(self):
        """Bearer uses full_filename, filename, or file as fallback."""
        result = {
            "findings": [
                {
                    "id": "rule",
                    "title": "test",
                    "severity": "high",
                    "filename": "fallback.py",
                    "line_number": 1,
                }
            ]
        }
        self.agg.aggregate("bearer", result)
        f = list(self.agg.findings.values())[0]
        assert f.component == "fallback.py"

    def test_source_line_numbers(self):
        """Line numbers from source object."""
        result = {
            "findings": [
                {
                    "id": "rule",
                    "title": "test",
                    "severity": "high",
                    "full_filename": "file.py",
                    "source": {
                        "start": 10,
                        "end": 20,
                        "column": {"start": 5, "end": 40},
                    },
                }
            ]
        }
        self.agg.aggregate("bearer", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["start"]["line"] == 10
        assert f.details["end"]["line"] == 20
        assert f.details["start"]["column"] == 5
        assert f.details["end"]["column"] == 40

    def test_empty_findings_list(self):
        self.agg.aggregate("bearer", {"findings": []})
        assert len(self.agg.findings) == 0

    def test_empty_findings_dict(self):
        self.agg.aggregate("bearer", {"findings": {}})
        assert len(self.agg.findings) == 0
