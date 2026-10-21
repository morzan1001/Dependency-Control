import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models.finding import FindingType
from app.schemas.bearer import BearerFinding
from app.services.aggregation import ResultAggregator

# bearer 2.1.1 `scan . --format json` over a Python file hashing a password with MD5 and logging an email.
_BEARER_OUTPUT = json.loads((Path(__file__).parents[2] / "fixtures/sast/bearer_2.1.1_findings.json").read_text())


def _kept_lines_and_skip_notice(agg: ResultAggregator, scanner: str) -> tuple[list[int], str]:
    notice = agg.findings[f"SCAN-ERROR-{scanner}"]
    assert notice.type == FindingType.SYSTEM_WARNING
    kept = [f.details["start"]["line"] for f in agg.findings.values() if f is not notice]
    return kept, notice.description


class TestNormalizeOpengrep:
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
            f = next(iter(agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
        assert f.details["cwe_ids"] == ["79", "89"]

    def test_a_reference_given_as_one_string_is_one_reference(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "test-rule",
                    "path": "file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {"severity": "ERROR", "message": "test", "metadata": {"references": "https://owasp.org"}},
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        [finding] = self.agg.findings.values()
        assert finding.details["references"] == ["https://owasp.org"]

    def test_an_unreadable_finding_is_dropped_and_the_rest_kept(self):
        def item(line: int, metadata: dict) -> dict:
            return {
                "check_id": "test-rule",
                "path": "file.py",
                "start": {"line": line, "col": 1},
                "end": {"line": line, "col": 10},
                "extra": {"severity": "ERROR", "message": "test", "metadata": metadata},
            }

        self.agg.aggregate("opengrep", self._opengrep_result([item(1, {"impact": ["HIGH"]}), item(2, {})]))

        assert _kept_lines_and_skip_notice(self.agg, "opengrep") == (
            [2],
            "Scanner 'opengrep' returned partial results: skipped 1 unreadable entry",
        )

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
        f = next(iter(self.agg.findings.values()))
        assert f.details["owasp"] == ["A01:2021"]

    def test_rule_name_in_description(self):
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
        f = next(iter(self.agg.findings.values()))
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

    def test_a_result_without_a_check_id_takes_the_shared_rule_placeholder(self):
        self.agg.aggregate("opengrep", self._opengrep_result([{"path": "app/views.py", "start": {"line": 3}}]))

        (finding,) = self.agg.get_findings()
        assert finding.details["sast_findings"][0]["id"] == "unknown"
        assert finding.id == "OPENGREP-unknown-app/views.py-3"

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
        f = next(iter(self.agg.findings.values()))
        assert f.details["start"] == {"line": 10, "column": 5}
        assert f.details["end"] == {"line": 15, "column": 20}

    def test_fingerprint_and_lines_survive_ingest(self):
        from app.schemas.opengrep import OpenGrepFinding

        raw = {
            "check_id": "rules.python.weak-rng",
            "path": "app/util.py",
            "start": {"line": 10, "col": 5},
            "end": {"line": 10, "col": 20},
            "extra": {
                "severity": "WARNING",
                "message": "weak rng",
                "metadata": {},
                "fingerprint": "abc123def456",
                "lines": "random.random()",
            },
        }
        dumped = OpenGrepFinding(**raw).model_dump()
        assert dumped["extra"]["fingerprint"] == "abc123def456"
        assert dumped["extra"]["lines"] == "random.random()"

        self.agg.aggregate("opengrep", {"results": [raw]})
        f = self.agg.get_findings()[0]
        entry = f.details["sast_findings"][0]["details"]
        assert entry["fingerprint"] == "abc123def456"
        assert entry["code_extract"] == "random.random()"

    def test_merged_sast_finding_stores_the_scanner_message_once(self):
        raw = {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app/util.py",
            "start": {"line": 10, "col": 5},
            "end": {"line": 10, "col": 20},
            "extra": {
                "severity": "ERROR",
                "message": "eval() on user input",
                "metadata": {"cwe": ["CWE-95"], "owasp": ["A03:2021"]},
                "lines": "eval(x)",
            },
        }
        self.agg.aggregate("opengrep", {"results": [raw]})
        [f] = self.agg.get_findings()

        assert set(f.details) == {"sast_findings", "file", "line"}
        [entry] = f.details["sast_findings"]
        assert set(entry) == {"id", "scanner", "severity", "details"}
        assert entry["details"]["cwe_ids"]
        assert f.description

    def test_an_unmapped_severity_stays_unknown_through_get_findings(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "rules.inventory.flask-route",
                    "path": "app/routes.py",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 20},
                    "extra": {"severity": "INVENTORY", "message": "route", "metadata": {}},
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        [f] = self.agg.get_findings()

        assert f.severity == "UNKNOWN"
        assert f.details["sast_findings"][0]["severity"] == "UNKNOWN"

    def test_opengrep_and_bearer_on_one_line_stay_two_findings(self):
        self.agg.aggregate(
            "opengrep",
            self._opengrep_result(
                [
                    {
                        "check_id": "python.lang.security.audit.sqli",
                        "path": "app/db.py",
                        "start": {"line": 10, "col": 5},
                        "end": {"line": 10, "col": 40},
                        "extra": {"severity": "ERROR", "message": "sqli", "metadata": {"cwe": ["CWE-89"]}},
                    }
                ]
            ),
        )
        self.agg.aggregate(
            "bearer",
            {
                "findings": [
                    {
                        "id": "python_lang_sql_injection",
                        "title": "SQL injection",
                        "severity": "high",
                        "full_filename": "app/db.py",
                        "line_number": 10,
                        "cwe_ids": ["89"],
                    }
                ]
            },
        )
        findings = self.agg.get_findings()

        assert sorted(f.id for f in findings) == [
            "BEARER-python_lang_sql_injection-app/db.py-10",
            "OPENGREP-python.lang.security.audit.sqli-app/db.py-10",
        ]
        for f in findings:
            [entry] = f.details["sast_findings"]
            assert f.scanners == [entry["scanner"]]
            assert (f.details["file"], f.details["line"]) == ("app/db.py", 10)

    def test_get_findings_sets_match_signature(self):
        result = self._opengrep_result(
            [
                {
                    "check_id": "rules.python.weak-rng",
                    "path": "app/util.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 20},
                    "extra": {
                        "severity": "WARNING",
                        "message": "m",
                        "metadata": {},
                        "fingerprint": "fp-xyz",
                        "lines": "random.random()",
                    },
                }
            ]
        )
        self.agg.aggregate("opengrep", result)
        f = self.agg.get_findings()[0]
        assert f.match is not None
        assert f.match.anchor == "fp-xyz"
        assert f.match.anchor_kind == "scanner_fp"


class TestNormalizeBearer:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_real_output_keeps_the_rule_doc_link_and_not_the_rule_doc(self):
        self.agg.aggregate("bearer", {"findings": _BEARER_OUTPUT})
        findings = sorted(self.agg.findings.values(), key=lambda f: f.details["rule_id"])

        assert [(f.description, f.severity) for f in findings] == [
            ("Leakage of sensitive information in logger message", "MEDIUM"),
            ("Usage of weak hashing library on a password (MD5)", "HIGH"),
        ]
        assert all(f.details["documentation_url"].startswith("https://docs.bearer.com/") for f in findings)
        assert all("full_description" not in f.details for f in findings)

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
            f = next(iter(agg.findings.values()))
            assert f.severity == expected, f"Bearer {bearer_sev} should map to {expected}"

    def test_grouped_by_severity_dict(self):
        result = {
            "findings": {
                "high": [{"id": "rule1", "title": "High issue", "full_filename": "a.py", "line_number": 1}],
                "low": [{"id": "rule2", "title": "Low issue", "full_filename": "b.py", "line_number": 1}],
            }
        }
        self.agg.aggregate("bearer", result)
        assert len(self.agg.findings) == 2

    def test_severity_injected_from_group_key(self):
        result = {"findings": {"high": [{"id": "rule1", "title": "test", "full_filename": "a.py", "line_number": 1}]}}
        self.agg.aggregate("bearer", result)
        f = next(iter(self.agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
        assert f.details["cwe_ids"] == ["79", "89"]

    def test_filename_fallback(self):
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
        f = next(iter(self.agg.findings.values()))
        assert f.component == "fallback.py"

    def test_end_line_falls_back_to_the_start_line(self):
        """An item without an end position spans its own line; a zero would invert the span."""
        result = {
            "findings": [
                {
                    "id": "rule",
                    "title": "test",
                    "severity": "high",
                    "full_filename": "file.py",
                    "line_number": 42,
                }
            ]
        }
        self.agg.aggregate("bearer", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["start"]["line"] == 42
        assert f.details["end"]["line"] == 42

    def test_source_line_numbers(self):
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
        f = next(iter(self.agg.findings.values()))
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


class TestBearerEntryContract:
    """One BearerFinding model governs /ingest and /adhoc, so an entry is read on both or on neither."""

    @pytest.mark.parametrize(
        "unreadable",
        [
            pytest.param({"rule_id": "r", "full_filename": "a.py", "line_number": 1}, id="without-a-rule-id"),
            pytest.param({"id": "r", "severity": 3, "full_filename": "a.py", "line_number": 1}, id="wrongly-typed"),
        ],
    )
    def test_an_unreadable_entry_is_dropped_and_its_siblings_kept(self, unreadable):
        agg = ResultAggregator()
        agg.aggregate("bearer", {"findings": [unreadable, {"id": "r", "full_filename": "a.py", "line_number": 2}]})

        assert _kept_lines_and_skip_notice(agg, "bearer") == (
            [2],
            "Scanner 'bearer' returned partial results: skipped 1 unreadable entry",
        )
        with pytest.raises(ValidationError):
            BearerFinding.model_validate(unreadable)

    def test_the_parent_snippet_stands_in_for_a_missing_code_extract(self):
        agg = ResultAggregator()
        agg.aggregate("bearer", {"findings": {"low": [{"id": "r", "full_filename": "a.py", "snippet": "log(email)"}]}})

        [finding] = agg.get_findings()
        assert finding.details["sast_findings"][0]["details"]["code_extract"] == "log(email)"
