from app.models.finding import Finding
from app.services.waivers.signature import compute_match_signature, compute_match_signature_from_doc, normalize_snippet


def _sast_merged(component, line, scanner, rule_id, fingerprint, code):
    """Build a Finding shaped like merge_sast_findings output (nested per-scanner entry)."""
    return Finding(
        id=f"{scanner.upper()}-{rule_id}-{component}-{line}",
        type="sast", severity="HIGH", component=component, description="d",
        scanners=[scanner],
        details={
            "sast_findings": [
                {"id": rule_id, "scanner": scanner, "severity": "HIGH", "title": "t", "description": "d",
                 "details": {"fingerprint": fingerprint, "code_extract": code, "start": {"line": line}}}
            ],
            "file": component, "line": line, "cwe_ids": [], "category_groups": [], "owasp": [],
        },
    )


class TestNormalizeSnippet:
    def test_whitespace_and_indent_irrelevant(self):
        assert normalize_snippet("  foo( a , b )  ") == normalize_snippet("foo( a , b )")
        assert normalize_snippet("foo(\n    a,\n    b)") == normalize_snippet("foo(\na,\nb)")

    def test_token_change_matters(self):
        assert normalize_snippet("foo(a)") != normalize_snippet("foo(b)")

    def test_empty_returns_none(self):
        assert normalize_snippet(None) is None
        assert normalize_snippet("   \n  ") is None


class TestSastSignature:
    def test_scanner_fp_anchor(self):
        f = _sast_merged("a.py", 10, "opengrep", "weak-rng", "fp-1", "random.random()")
        sig = compute_match_signature(f)
        assert sig.rule_key == "opengrep:weak-rng"
        assert sig.file_key == "a.py"
        assert sig.anchor == "fp-1"
        assert sig.anchor_kind == "scanner_fp"
        assert sig.last_line == 10
        assert sig.content_hash is not None

    def test_missing_fingerprint_degrades_to_content_hash(self):
        f = _sast_merged("a.py", 10, "opengrep", "weak-rng", None, "random.random()")
        sig = compute_match_signature(f)
        assert sig.anchor_kind == "content_hash"
        assert sig.content_hash is not None
        assert sig.is_strong is False

    def test_deterministic_scanner_selection_prefers_opengrep(self):
        f = _sast_merged("a.py", 10, "opengrep", "r", "fp-og", "code")
        # add a bearer entry in non-preferred order
        f.details["sast_findings"].insert(0, {
            "id": "r", "scanner": "bearer", "severity": "HIGH", "title": "t", "description": "d",
            "details": {"fingerprint": "fp-bearer", "code_extract": "code", "start": {"line": 10}},
        })
        sig = compute_match_signature(f)
        assert sig.anchor == "fp-og"  # opengrep preferred regardless of list order
        assert sig.rule_key == "opengrep:r"

    def test_empty_code_extract_sentinel(self):
        f = _sast_merged("a.py", 10, "opengrep", "r", "fp-1", None)
        sig = compute_match_signature(f)
        assert sig.anchor == "fp-1"
        assert sig.content_hash is None  # sentinel, not sha1("")


class TestIacSignature:
    def _kics(self, similarity_id=None, search_key="k", actual="public", expected="private", line=5):
        return Finding(
            id=f"KICS-q1-main.tf-{line}", type="iac", severity="HIGH", component="main.tf",
            description="d", scanners=["kics"],
            details={"rule_id": "q1", "search_key": search_key, "similarity_id": similarity_id,
                     "actual_value": actual, "expected_value": expected, "start": {"line": line}},
        )

    def test_similarity_id_preferred(self):
        sig = compute_match_signature(self._kics(similarity_id="sim-1"))
        assert sig.rule_key == "KICS:q1"
        assert sig.anchor == "sim-1"
        assert sig.anchor_kind == "similarity_id"
        assert sig.content_hash is not None
        assert sig.last_line == 5

    def test_search_key_fallback(self):
        sig = compute_match_signature(self._kics(similarity_id=None, search_key="resource.x"))
        assert sig.anchor == "resource.x"
        assert sig.anchor_kind == "search_key"

    def test_no_anchor_degrades(self):
        sig = compute_match_signature(self._kics(similarity_id=None, search_key=None))
        assert sig.anchor_kind == "content_hash"


class TestSecretSignature:
    def test_hash_from_id(self):
        f = Finding(id="SECRET-aws-1a2b3c4d", type="secret", severity="CRITICAL",
                    component="env.sh", description="d", scanners=["trufflehog"],
                    details={"detector": "aws"})
        sig = compute_match_signature(f)
        assert sig.rule_key == "aws"
        assert sig.anchor == "1a2b3c4d"
        assert sig.anchor_kind == "secret_hash"
        assert sig.content_hash == "1a2b3c4d"


class TestNonLocationFindings:
    def test_vulnerability_returns_none(self):
        f = Finding(id="CVE-2021-1", type="vulnerability", severity="HIGH", component="lodash",
                    description="d", scanners=["grype"], details={})
        assert compute_match_signature(f) is None


def test_compute_match_signature_from_doc_recovers_bearer_sast():
    # A persisted finding doc with NO "match" field but with the merged SAST details
    # the aggregator would have stored. Recompute must yield the same signature shape.
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
                    "details": {"fingerprint": "edb203_2", "code_extract": "X=\"s\"", "start": {"line": 94}},
                }
            ],
        },
    }
    sig = compute_match_signature_from_doc(doc)
    assert sig is not None
    assert sig.rule_key == "bearer:java_lang_hardcoded_secret"
    assert sig.file_key == "a.py"
    assert sig.anchor == "edb203_2"
    assert sig.anchor_kind == "scanner_fp"
    assert sig.last_line == 94


def test_compute_match_signature_from_doc_none_for_non_location():
    assert compute_match_signature_from_doc({"finding_id": "CVE-2021-1", "component": "pkg", "details": {}}) is None


def test_finding_and_raw_doc_produce_same_signature():
    """Cross-path equivalence: compute_match_signature(Finding) == compute_match_signature_from_doc(doc)
    for the same logical finding.  Guards against a silent finding_id→id field-name mismatch."""
    finding = _sast_merged("src/auth.py", 94, "bearer", "java_lang_hardcoded_secret", "edb203_2", 'API_KEY="s3cr3t"')
    doc = {
        "finding_id": finding.id,
        "component": finding.component,
        "type": "sast",
        "details": finding.details,
    }
    sig_finding = compute_match_signature(finding)
    sig_doc = compute_match_signature_from_doc(doc)
    assert sig_finding is not None, "compute_match_signature returned None for a valid SAST finding"
    assert sig_doc is not None, "compute_match_signature_from_doc returned None for the equivalent doc"
    assert sig_finding.model_dump() == sig_doc.model_dump()
