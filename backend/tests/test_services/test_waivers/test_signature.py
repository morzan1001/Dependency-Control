from app.models.finding import Finding
from app.services.waivers.signature import compute_match_signature, snippet_hash


def _signature(finding: Finding):
    return compute_match_signature(finding.id, finding.details, finding.component)


def _doc_signature(doc: dict):
    return compute_match_signature(doc["finding_id"], doc["details"], doc["component"])


def _sast_merged(component, line, scanner, rule_id, fingerprint, code):
    """Build a Finding shaped like to_sast_aggregate output (nested per-scanner entry)."""
    return Finding(
        id=f"{scanner.upper()}-{rule_id}-{component}-{line}",
        type="sast",
        severity="HIGH",
        component=component,
        description="d",
        scanners=[scanner],
        details={
            "sast_findings": [
                {
                    "id": rule_id,
                    "scanner": scanner,
                    "severity": "HIGH",
                    "title": "t",
                    "description": "d",
                    "details": {"fingerprint": fingerprint, "code_extract": code, "start": {"line": line}},
                }
            ],
            "file": component,
            "line": line,
            "cwe_ids": [],
            "category_groups": [],
            "owasp": [],
        },
    )


class TestSnippetHash:
    def test_whitespace_and_indent_irrelevant(self):
        assert snippet_hash("  foo( a , b )  ") == snippet_hash("foo( a , b )")
        assert snippet_hash("foo(\n    a,\n    b)") == snippet_hash("foo(\na,\nb)")

    def test_token_change_matters(self):
        assert snippet_hash("foo(a)") != snippet_hash("foo(b)")

    def test_empty_returns_none(self):
        assert snippet_hash(None) is None
        assert snippet_hash("   \n  ") is None


class TestSastSignature:
    def test_scanner_fp_anchor(self):
        f = _sast_merged("a.py", 10, "opengrep", "weak-rng", "fp-1", "random.random()")
        sig = _signature(f)
        assert sig.rule_key == "opengrep:weak-rng"
        assert sig.file_key == "a.py"
        assert sig.anchor == "fp-1"
        assert sig.anchor_kind == "scanner_fp"
        assert sig.last_line == 10
        assert sig.content_hash is not None

    def test_missing_fingerprint_degrades_to_content_hash(self):
        f = _sast_merged("a.py", 10, "opengrep", "weak-rng", None, "random.random()")
        sig = _signature(f)
        assert sig.anchor_kind == "content_hash"
        assert sig.content_hash is not None
        assert sig.is_strong is False

    def test_deterministic_scanner_selection_prefers_opengrep(self):
        f = _sast_merged("a.py", 10, "opengrep", "r", "fp-og", "code")
        # add a bearer entry in non-preferred order
        f.details["sast_findings"].insert(
            0,
            {
                "id": "r",
                "scanner": "bearer",
                "severity": "HIGH",
                "title": "t",
                "description": "d",
                "details": {"fingerprint": "fp-bearer", "code_extract": "code", "start": {"line": 10}},
            },
        )
        sig = _signature(f)
        assert sig.anchor == "fp-og"  # opengrep preferred regardless of list order
        assert sig.rule_key == "opengrep:r"

    def test_empty_code_extract_sentinel(self):
        f = _sast_merged("a.py", 10, "opengrep", "r", "fp-1", None)
        sig = _signature(f)
        assert sig.anchor == "fp-1"
        assert sig.content_hash is None  # sentinel, not sha1("")


class TestIacSignature:
    def _kics(self, similarity_id=None, search_key="k", actual="public", expected="private", line=5):
        return Finding(
            id=f"KICS-q1-main.tf-{line}",
            type="iac",
            severity="HIGH",
            component="main.tf",
            description="d",
            scanners=["kics"],
            details={
                "rule_id": "q1",
                "search_key": search_key,
                "similarity_id": similarity_id,
                "actual_value": actual,
                "expected_value": expected,
                "start": {"line": line},
            },
        )

    def test_similarity_id_preferred(self):
        sig = _signature(self._kics(similarity_id="sim-1"))
        assert sig.rule_key == "KICS:q1"
        assert sig.anchor == "sim-1"
        assert sig.anchor_kind == "similarity_id"
        assert sig.content_hash is not None
        assert sig.last_line == 5

    def test_search_key_fallback(self):
        sig = _signature(self._kics(similarity_id=None, search_key="resource.x"))
        assert sig.anchor == "resource.x"
        assert sig.anchor_kind == "search_key"

    def test_no_anchor_degrades(self):
        sig = _signature(self._kics(similarity_id=None, search_key=None))
        assert sig.anchor_kind == "content_hash"


class TestSecretSignature:
    def test_hash_from_id(self):
        f = Finding(
            id="SECRET-aws-1a2b3c4d",
            type="secret",
            severity="CRITICAL",
            component="env.sh",
            description="d",
            scanners=["trufflehog"],
            details={"detector": "aws"},
        )
        sig = _signature(f)
        assert sig.rule_key == "aws"
        assert sig.anchor == "1a2b3c4d"
        assert sig.anchor_kind == "secret_hash"
        assert sig.content_hash == "1a2b3c4d"


class TestNonLocationFindings:
    def test_vulnerability_returns_none(self):
        f = Finding(
            id="CVE-2021-1",
            type="vulnerability",
            severity="HIGH",
            component="lodash",
            description="d",
            scanners=["grype"],
            details={},
        )
        assert _signature(f) is None


def test_compute_match_signature_from_doc_recovers_bearer_sast():
    # persisted doc with no "match" field must recompute to the same signature shape
    doc = {
        "finding_id": "BEARER-java_lang_hardcoded_secret-a.py-94",
        "component": "a.py",
        "type": "sast",
        "details": {
            "line": 94,
            "sast_findings": [
                {
                    "scanner": "bearer",
                    "id": "java_lang_hardcoded_secret",
                    "details": {"fingerprint": "edb203_2", "code_extract": 'X="s"', "start": {"line": 94}},
                }
            ],
        },
    }
    sig = _doc_signature(doc)
    assert sig is not None
    assert sig.rule_key == "bearer:java_lang_hardcoded_secret"
    assert sig.file_key == "a.py"
    assert sig.anchor == "edb203_2"
    assert sig.anchor_kind == "scanner_fp"
    assert sig.last_line == 94


def test_compute_match_signature_from_doc_none_for_non_location():
    assert _doc_signature({"finding_id": "CVE-2021-1", "component": "pkg", "details": {}}) is None


def test_sast_signature_collects_all_scanner_rule_keys():
    doc = {
        "finding_id": "BEARER-r-a.py-10",
        "component": "a.py",
        "type": "sast",
        "details": {
            "line": 10,
            "sast_findings": [
                {"scanner": "bearer", "id": "X", "details": {"fingerprint": "fpB", "start": {"line": 10}}},
                {"scanner": "opengrep", "id": "X", "details": {"fingerprint": "fpO", "start": {"line": 10}}},
            ],
        },
    }
    sig = _doc_signature(doc)
    assert sig is not None
    assert sig.rule_keys == ["bearer:X", "opengrep:X"]
    assert sig.rule_key in sig.rule_keys


def test_iac_signature_rule_keys_is_single():
    doc = {
        "finding_id": "KICS-q1-main.tf-3",
        "component": "main.tf",
        "type": "iac",
        "details": {"rule_id": "q1", "similarity_id": "s", "start": {"line": 3}},
    }
    sig = _doc_signature(doc)
    assert sig is not None
    assert sig.rule_keys == ["KICS:q1"]


def _aggregated(normalize, result):
    from app.services.aggregation import ResultAggregator

    aggregator = ResultAggregator()
    normalize(aggregator, result)
    return aggregator.get_findings()


def _opengrep_item(line, fingerprint, lines, check_id="python.lang.sqli", path="app/db.py"):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 20},
        "extra": {"severity": "ERROR", "message": "m", "fingerprint": fingerprint, "lines": lines},
    }


def test_semgrep_login_placeholder_never_anchors_and_never_shows_as_code():
    from app.services.normalizers.sast import normalize_opengrep

    findings = _aggregated(
        normalize_opengrep,
        {
            "results": [
                _opengrep_item(10, "requires login", "requires login"),
                _opengrep_item(50, "requires login", "requires login"),
            ]
        },
    )

    sigs = [f.match for f in findings]
    assert all(s.anchor_kind == "content_hash" and not s.is_strong for s in sigs)
    assert sigs[0].anchor != sigs[1].anchor
    entries = [f.details["sast_findings"][0]["details"] for f in findings]
    assert all("fingerprint" not in e and "code_extract" not in e for e in entries)


def test_bearer_ordinal_fingerprint_never_anchors():
    from app.services.normalizers.sast import normalize_bearer

    item = {
        "id": "python_lang_sqli",
        "filename": "app/db.py",
        "line_number": 20,
        "code_extract": "cursor.execute(q_b)",
        "fingerprint": "edb203edb203edb203edb203edb20300_1",
        "old_fingerprint": "edb203edb203edb203edb203edb20300_4",
        "severity": "high",
        "title": "SQLi",
    }
    (finding,) = _aggregated(normalize_bearer, {"findings": [item]})

    assert finding.match.anchor_kind == "content_hash"
    assert finding.match.anchor == snippet_hash("cursor.execute(q_b)")
    assert "fingerprint" not in finding.details["sast_findings"][0]["details"]


def test_a_finding_without_fingerprint_or_snippet_is_bound_to_its_line():
    no_evidence = [_sast_merged("a.py", line, "opengrep", "r", None, None) for line in (10, 11)]
    sigs = [_signature(f) for f in no_evidence]
    assert all(s.anchor_kind == "content_hash" and s.anchor == s.content_hash for s in sigs)
    assert sigs[0].anchor is not None
    assert sigs[0].anchor != sigs[1].anchor


def test_a_crypto_misuse_opengrep_finding_gets_a_scanner_fingerprint_signature():
    from app.services.normalizers.sast import normalize_opengrep

    item = _opengrep_item(12, "fp-crypto", "key = b'x'", check_id="crypto-misuse-hardcoded-key", path="src/a.py")
    (finding,) = _aggregated(normalize_opengrep, {"results": [item]})

    assert finding.type == "crypto_key_management"
    assert finding.match.anchor_kind == "scanner_fp"
    assert finding.match.anchor == "fp-crypto"
    assert finding.match.rule_key == "opengrep:crypto-misuse-hardcoded-key"
    assert finding.match.last_line == 12
