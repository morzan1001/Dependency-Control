"""Which analyzers the ad-hoc endpoint runs, and why the others do not."""

from app.schemas.adhoc import AnalyzerReport
from app.services.analysis.adhoc import (
    ADHOC_DEFAULT_ANALYZERS,
    ADHOC_SKIP_REASONS,
    resolve_adhoc_analyzers,
)
from app.services.analysis.registry import analyzers

_OSV = "osv"
_LICENSE = "license_compliance"
_TRIVY = "trivy"
_GRYPE = "grype"
_CRYPTO = "crypto_weak_algorithm"
_ENRICHMENT = "epss_kev"
_UNKNOWN_NAME = "not_a_scanner"
_UNKNOWN_REASON = "unknown analyzer"
_NOT_REQUESTED = "not requested"
_UNCACHED_FANOUT_MARKER = "publishes nothing to the shared cache"
_TYPOSQUATTING_MARKER = "top-packages list"
_CRYPTO_STAGE = "crypto_rules"
_CRYPTO_STORED_ASSETS = "stored crypto assets"
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

    assert set(selected) | set(report.skipped) == set(analyzers)
    assert not set(selected) & set(report.skipped)


def test_cli_scanners_are_off_by_default_and_quote_their_real_timeout():
    report = AnalyzerReport()

    resolve_adhoc_analyzers(None, report)

    for name in (_TRIVY, _GRYPE):
        assert report.skipped[name] == ADHOC_SKIP_REASONS[name]
        assert str(analyzers[name].cli_timeout) in report.skipped[name]


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
    # The registered analyzer returns an empty result without a scan to read assets from, so
    # the reason has to point at the stage that evaluates the same rules on the posted CBOM.
    assert _CRYPTO_STORED_ASSETS in reason
    assert _CRYPTO_STAGE in reason


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
    assert set(report.skipped) == set(analyzers)
