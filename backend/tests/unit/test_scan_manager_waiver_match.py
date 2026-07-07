from app.models.finding import Finding
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.services.scan_manager import ScanManager


def _finding(anchor):
    return Finding(id="OPENGREP-r-a.py-10", type="sast", severity="HIGH", component="a.py",
                   description="d", scanners=["opengrep"],
                   match=MatchSignature(rule_key="opengrep:r", file_key="a.py", anchor=anchor,
                                        anchor_kind="scanner_fp", content_hash="c1", last_line=10))


def _waiver(anchor, status="false_positive"):
    return Waiver(reason="r", created_by="u", status=status,
                  match=MatchSignature(rule_key="opengrep:r", file_key="a.py", anchor=anchor,
                                       anchor_kind="scanner_fp", content_hash="c1", last_line=10))


class TestInMemoryStrongMatch:
    def test_exact_anchor_matches(self):
        assert ScanManager._finding_matches_waiver(ScanManager, _finding("fpA"), _waiver("fpA")) is True

    def test_different_anchor_no_match(self):
        # ingest is best-effort exact-only: a moved/edited finding is NOT matched here (recalc handles it)
        assert ScanManager._finding_matches_waiver(ScanManager, _finding("fpB"), _waiver("fpA")) is False


def _legacy_finding(finding_id, ftype, component, version=None):
    """A finding without a match signature (license/eol/vuln/secret-by-type)."""
    return Finding(id=finding_id, type=ftype, severity="HIGH", component=component,
                   version=version, description="d", scanners=["s"])


def _legacy_waiver(finding_type=None, package_name=None, package_version=None, finding_id=None):
    return Waiver(reason="r", created_by="u", status="false_positive",
                  finding_type=finding_type, package_name=package_name,
                  package_version=package_version, finding_id=finding_id)


class TestLegacyWaiverAndSemantics:
    def test_type_match_but_different_component_is_not_waived(self):
        # Regression: legacy OR semantics waived EVERY secret in the upload when a
        # single-file secret waiver existed. AND semantics must NOT waive a secret in
        # a different file.
        waiver = _legacy_waiver(finding_type="secret", package_name="src/config.js")
        finding = _legacy_finding("SECRET-x", "secret", "src/other.js")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is False

    def test_all_set_fields_match_is_waived(self):
        waiver = _legacy_waiver(finding_type="secret", package_name="src/config.js")
        finding = _legacy_finding("SECRET-x", "secret", "src/config.js")
        assert ScanManager._finding_matches_waiver(ScanManager, finding, waiver) is True

    def test_package_version_must_match(self):
        waiver = _legacy_waiver(package_name="requests", package_version="2.26.0")
        # component matches but version differs -> not waived (version is ANDed)
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
