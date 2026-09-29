"""The chat remediation plan picks its target by the aggregate fixed_version's ordering."""

from app.services.chat.tools._helpers import _compare_versions


def test_debian_revisions_compare_numerically():
    assert _compare_versions("1.2.3-10", "1.2.3-2") == 1
    assert _compare_versions("1.2.3-2", "1.2.3-10") == -1


def test_equal_spellings_compare_equal():
    assert _compare_versions("v1.2.0", "1.2.0") == 0
