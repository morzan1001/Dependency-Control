"""Tests for update frequency analysis — version classification."""

from app.services.update_frequency import classify_version_change


class TestClassifyVersionChange:
    def test_major_bump(self):
        assert classify_version_change("1.0.0", "2.0.0") == "major"

    def test_minor_bump(self):
        assert classify_version_change("1.0.0", "1.1.0") == "minor"

    def test_patch_bump(self):
        assert classify_version_change("1.0.0", "1.0.1") == "patch"

    def test_v_prefix_accepted(self):
        assert classify_version_change("v1.0.0", "v1.0.1") == "patch"

    def test_unparseable_returns_unknown(self):
        assert classify_version_change("abc123", "def456") == "unknown"

    def test_one_unparseable_returns_unknown(self):
        assert classify_version_change("1.0.0", "abc") == "unknown"

    # A2: identical versions must NOT be classified as "patch"
    def test_identical_versions_returns_none(self):
        assert classify_version_change("1.0.0", "1.0.0") == "none"

    def test_identical_with_v_prefix_returns_none(self):
        assert classify_version_change("v1.0.0", "1.0.0") == "none"

    # A3: pre-release identifiers must be respected
    def test_stable_to_prerelease_is_not_no_change(self):
        # 1.0.0 -> 1.0.0-beta1 is a real change (downgrade), must not be "none"
        result = classify_version_change("1.0.0", "1.0.0-beta1")
        assert result != "none"
        assert result in ("patch", "prerelease")

    def test_prerelease_to_stable_is_not_no_change(self):
        # 1.0.0-beta1 -> 1.0.0 is a real change (graduation), must not be "none"
        result = classify_version_change("1.0.0-beta1", "1.0.0")
        assert result != "none"
        assert result in ("patch", "prerelease")

    def test_prerelease_to_different_prerelease(self):
        # 1.0.0-beta1 -> 1.0.0-beta2: same release tuple, different prerelease
        result = classify_version_change("1.0.0-beta1", "1.0.0-beta2")
        assert result != "none"
        assert result in ("patch", "prerelease")

    def test_prerelease_to_higher_patch(self):
        # 1.0.0-beta1 -> 1.0.1 spans both prerelease and patch — should be patch
        assert classify_version_change("1.0.0-beta1", "1.0.1") == "patch"

    def test_prerelease_to_higher_major(self):
        assert classify_version_change("1.0.0-beta1", "2.0.0") == "major"

    def test_short_version_strings(self):
        # Versions like "1.0" should still parse and classify
        assert classify_version_change("1.0", "1.1") == "minor"

    def test_single_component_version(self):
        # A bare "1" -> "2" is a major change
        assert classify_version_change("1", "2") == "major"
