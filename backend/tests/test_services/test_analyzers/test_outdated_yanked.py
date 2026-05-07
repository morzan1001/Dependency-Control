"""Tests for yanked-version detection (A8) inside the outdated analyzer.

A version that was published and then withdrawn from the registry is
strictly more dangerous than a merely outdated version — the upstream
authors took action to retract it, often because of a security or
correctness defect. Our scans were treating those as legitimate
installations. The detection helper here flags them so the SBOM
report can surface a finding."""

from app.services.analyzers.outdated import is_version_withdrawn


def _v(version: str, withdrawn: bool = False, default: bool = False) -> dict:
    entry = {"versionKey": {"version": version}}
    if withdrawn:
        entry["isWithdrawn"] = True
    if default:
        entry["isDefault"] = True
    return entry


class TestIsVersionWithdrawn:
    def test_returns_true_when_target_is_withdrawn(self):
        versions = [_v("1.0.0", withdrawn=True), _v("1.0.1", default=True)]
        assert is_version_withdrawn(versions, "1.0.0") is True

    def test_returns_false_when_target_is_active(self):
        versions = [_v("1.0.0"), _v("1.0.1", default=True)]
        assert is_version_withdrawn(versions, "1.0.0") is False

    def test_returns_false_when_target_not_found(self):
        # Conservative default: if we don't have the data, don't claim yanked.
        versions = [_v("1.0.0"), _v("1.0.1")]
        assert is_version_withdrawn(versions, "9.9.9") is False

    def test_handles_empty_versions_list(self):
        assert is_version_withdrawn([], "1.0.0") is False

    def test_only_target_version_matters(self):
        # Other withdrawn entries in the list don't matter — we only care
        # about the version actually installed.
        versions = [
            _v("0.9.0", withdrawn=True),  # old, withdrawn, not what we have
            _v("1.0.0"),
            _v("1.0.1", default=True),
        ]
        assert is_version_withdrawn(versions, "1.0.0") is False

    def test_handles_malformed_entries(self):
        # deps.dev occasionally returns sparse entries; the parser must
        # not crash on them.
        versions = [
            {},  # empty
            {"versionKey": {}},  # no version key
            {"versionKey": {"version": "1.0.0"}, "isWithdrawn": True},
        ]
        assert is_version_withdrawn(versions, "1.0.0") is True

    def test_v_prefix_matches_canonical_form(self):
        # PyPI / npm versions are stored without the "v" prefix in deps.dev.
        # The lookup compares the literal string, but we strip leading "v"
        # from the target to keep parity with how OutdatedAnalyzer normalises.
        versions = [_v("1.0.0", withdrawn=True)]
        assert is_version_withdrawn(versions, "v1.0.0") is True
