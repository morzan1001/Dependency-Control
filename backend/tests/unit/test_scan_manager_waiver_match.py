from app.models.finding import Finding
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.services.scan_manager import ScanManager


def _finding(anchor):
    return Finding(
        id="OPENGREP-r-a.py-10",
        type="sast",
        severity="HIGH",
        component="a.py",
        description="d",
        scanners=["opengrep"],
        match=MatchSignature(
            rule_key="opengrep:r",
            file_key="a.py",
            anchor=anchor,
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=10,
        ),
    )


def _waiver(anchor, status="false_positive"):
    return Waiver(
        reason="r",
        created_by="u",
        status=status,
        match=MatchSignature(
            rule_key="opengrep:r",
            file_key="a.py",
            anchor=anchor,
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=10,
        ),
    )


class TestInMemoryStrongMatch:
    def test_exact_anchor_matches(self):
        assert ScanManager._finding_matches_waiver(ScanManager, _finding("fpA"), _waiver("fpA")) is True

    def test_different_anchor_no_match(self):
        # ingest is best-effort exact-only: a moved/edited finding is NOT matched here (recalc handles it)
        assert ScanManager._finding_matches_waiver(ScanManager, _finding("fpB"), _waiver("fpA")) is False


def _legacy_finding(finding_id, ftype, component, version=None):
    """A finding without a match signature (license/eol/vuln/secret-by-type)."""
    return Finding(
        id=finding_id,
        type=ftype,
        severity="HIGH",
        component=component,
        version=version,
        description="d",
        scanners=["s"],
    )


def _legacy_waiver(finding_type=None, package_name=None, package_version=None, finding_id=None):
    return Waiver(
        reason="r",
        created_by="u",
        status="false_positive",
        finding_type=finding_type,
        package_name=package_name,
        package_version=package_version,
        finding_id=finding_id,
    )


class TestLegacyWaiverAndSemantics:
    def test_type_match_but_different_component_is_not_waived(self):
        # AND semantics: a type+file secret waiver must not waive a secret in a different file.
        waiver = _legacy_waiver(finding_type="secret", package_name="src/config.js")
        finding = _legacy_finding("SECRET-x", "secret", "src/other.js")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is False

    def test_all_set_fields_match_is_waived(self):
        waiver = _legacy_waiver(finding_type="secret", package_name="src/config.js")
        finding = _legacy_finding("SECRET-x", "secret", "src/config.js")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is True

    def test_package_version_must_match(self):
        waiver = _legacy_waiver(package_name="requests", package_version="2.26.0")
        # version is ANDed: component matches but differing version is not waived
        finding = _legacy_finding("CVE-1", "vulnerability", "requests", version="2.27.0")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is False
        finding_ok = _legacy_finding("CVE-1", "vulnerability", "requests", version="2.26.0")
        assert ScanManager._finding_matches_waiver(ScanManager, finding_ok, waiver) is True

    def test_component_only_waiver_matches_by_component(self):
        waiver = _legacy_waiver(package_name="requests")
        finding = _legacy_finding("CVE-1", "vulnerability", "requests")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is True

    def test_empty_waiver_matches_nothing(self):
        waiver = _legacy_waiver()
        finding = _legacy_finding("CVE-1", "vulnerability", "requests")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is False


def _ingested(finding_id, ftype, component, details, match=None):
    return Finding(
        id=finding_id,
        type=ftype,
        severity="HIGH",
        component=component,
        description="d",
        scanners=["s"],
        details=details,
        match=match,
    )


class TestIngestHonoursScopeAndRule:
    def test_a_rule_scope_secret_waiver_reaches_the_detector_in_another_file(self):
        waiver = Waiver(
            reason="r",
            created_by="u",
            scope="rule",
            rule_id="17",
            finding_id="SECRET-17-aaaa1111",
            package_name="src/a.env",
            finding_type="secret",
        )
        other_file = _ingested("SECRET-17-bbbb2222", "secret", "src/b.env", {"detector": "17"})
        other_detector = _ingested("SECRET-18-cccc3333", "secret", "src/a.env", {"detector": "18"})

        assert ScanManager._finding_matches_waiver(ScanManager, other_file, waiver) is True
        assert ScanManager._finding_matches_waiver(ScanManager, other_detector, waiver) is False

    def test_a_file_scope_waiver_reaches_another_line_of_its_rule(self):
        waiver = Waiver(
            reason="r",
            created_by="u",
            scope="file",
            rule_id="r",
            finding_id="OPENGREP-r-a.py-10",
            package_name="a.py",
            finding_type="sast",
        )
        moved = _ingested("OPENGREP-r-a.py-42", "sast", "a.py", {"sast_findings": [{"id": "r", "scanner": "opengrep"}]})

        assert ScanManager._finding_matches_waiver(ScanManager, moved, waiver) is True

    def test_a_rule_scope_waiver_carrying_a_signature_keeps_rule_semantics(self):
        waiver = _waiver("fpA")
        waiver.scope = "rule"
        waiver.rule_id = "r"
        elsewhere = _ingested(
            "OPENGREP-r-b.py-3",
            "sast",
            "b.py",
            {"sast_findings": [{"id": "r", "scanner": "opengrep"}]},
            match=_finding("fpB").match,
        )

        assert ScanManager._finding_matches_waiver(ScanManager, elsewhere, waiver) is True

    def test_a_vulnerability_waiver_never_waives_a_whole_document(self):
        waiver = Waiver(reason="r", created_by="u", vulnerability_id="CVE-1", package_name="requests")

        assert (
            ScanManager._finding_matches_waiver(
                ScanManager, _legacy_finding("CVE-1", "vulnerability", "requests"), waiver
            )
            is False
        )
