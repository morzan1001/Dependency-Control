"""Tests for the human-readable message Trivy findings carry."""

import pytest

from app.services.analyzers.trivy import TrivyAnalyzer


@pytest.mark.parametrize(
    ("title", "fixed_version", "expected"),
    [
        ("Heap overflow", "", "CVE-1: Heap overflow"),
        ("", "", "CVE-1 in openssl@1.0"),
        ("", "1.1", "CVE-1 in openssl@1.0 (fix available: 1.1)"),
        ("Heap overflow", "1.1", "CVE-1: Heap overflow (fix available: 1.1)"),
    ],
)
def test_message_prefers_the_title_and_names_an_available_fix(title, fixed_version, expected):
    assert TrivyAnalyzer()._create_message("CVE-1", "openssl", "1.0", fixed_version, title) == expected
