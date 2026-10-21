from app.schemas.adhoc import AnalyzerReport
from app.services.analysis.adhoc import ADHOC_DEFAULT_ANALYZERS, resolve_adhoc_analyzers
from app.services.analysis.registry import CRYPTO_ANALYZERS, analyzer_factories

_OSV = "osv"
_LICENSE = "license_compliance"
_TRIVY = "trivy"
_GRYPE = "grype"
_CRYPTO = "crypto_weak_algorithm"
_ENRICHMENT = "epss_kev"
_UNKNOWN_NAME = "not_a_scanner"
_UNKNOWN_REASON = "unknown analyzer"
_NOT_REQUESTED = "not requested"
_CLI_SCANNER_REASON = "off by default: runs a CLI scanner process, which takes minutes on large SBOMs"
_UNCACHED_FANOUT_MARKER = "caches nothing keyed on the posted packages"
_TYPOSQUATTING_MARKER = "top-packages list"
_CRYPTO_STAGE = "crypto_rules"
_CRYPTO_STORED_ASSETS = "stored crypto assets"
# These two grade against the wall clock and the IANA catalog, not a policy rule, so the stage covers neither.
_CERT_LIFECYCLE = "crypto_certificate_lifecycle"
_PROTOCOL_CIPHER = "crypto_protocol_cipher"
_NO_EQUIVALENT = "no ad-hoc equivalent"
_REPLACEMENT_CLAIM = "replaced ad-hoc"
_FANOUT_ANALYZERS = (
    "deps_dev",
    "outdated_packages",
    "hash_verification",
    "end_of_life",
    "maintainer_risk",
    "os_malware",
)


def test_default_selection_is_the_declared_allowlist():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers(None, report)

    assert selected == list(ADHOC_DEFAULT_ANALYZERS)
    assert selected == [_OSV, _LICENSE]


def test_every_registered_analyzer_is_either_selected_or_given_a_reason():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers(None, report)

    assert set(selected) | set(report.skipped) == set(analyzer_factories) | CRYPTO_ANALYZERS
    assert not set(selected) & set(report.skipped)


def test_cli_scanners_are_off_by_default_without_quoting_a_bound_their_retries_exceed():
    report = AnalyzerReport()

    resolve_adhoc_analyzers(None, report)

    assert report.skipped[_TRIVY] == report.skipped[_GRYPE] == _CLI_SCANNER_REASON


def test_registry_fanout_analyzers_are_off_by_default_with_an_uncached_reason():
    report = AnalyzerReport()

    resolve_adhoc_analyzers(None, report)

    for name in _FANOUT_ANALYZERS:
        assert _UNCACHED_FANOUT_MARKER in report.skipped[name], name
    assert _TYPOSQUATTING_MARKER in report.skipped["typosquatting"]


def test_explicit_request_overrides_the_default_and_clears_the_skip_note():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers([_GRYPE, _OSV], report)

    assert selected == [_GRYPE, _OSV]
    assert _GRYPE not in report.skipped
    assert report.skipped[_LICENSE] == _NOT_REQUESTED


def test_crypto_analyzers_cannot_be_requested_and_name_their_replacement():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers([_CRYPTO], report)

    assert selected == []
    reason = report.skipped[_CRYPTO]
    # Without a scan the registered analyzer finds nothing, so the reason points at the stage that evaluates the CBOM.
    assert _CRYPTO_STORED_ASSETS in reason
    assert _CRYPTO_STAGE in reason


def test_a_crypto_analyzer_the_stage_does_not_cover_says_so_instead_of_claiming_a_replacement():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers([_CERT_LIFECYCLE, _PROTOCOL_CIPHER], report)

    assert selected == []
    for name in (_CERT_LIFECYCLE, _PROTOCOL_CIPHER):
        assert _NO_EQUIVALENT in report.skipped[name], name
        assert _REPLACEMENT_CLAIM not in report.skipped[name], name


def test_a_post_processor_name_is_not_reported_as_an_unknown_analyzer():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers([_ENRICHMENT], report)

    assert selected == []
    assert _ENRICHMENT not in report.skipped


def test_unknown_analyzer_is_surfaced_not_swallowed():
    report = AnalyzerReport()

    selected = resolve_adhoc_analyzers([_UNKNOWN_NAME], report)

    assert selected == []
    assert report.skipped[_UNKNOWN_NAME] == _UNKNOWN_REASON


def test_empty_explicit_list_runs_nothing():
    report = AnalyzerReport()

    assert resolve_adhoc_analyzers([], report) == []
    assert set(report.skipped) == set(analyzer_factories) | CRYPTO_ANALYZERS


def test_an_analyzer_named_twice_runs_once():
    report = AnalyzerReport()

    assert resolve_adhoc_analyzers([_OSV, _OSV], report) == [_OSV]
