"""Unit tests for SPDX expression tokenization."""

from app.services.analyzers.license_compliance.normalizer import tokenize_license_string


def test_composite_and_expression_splits_into_units():
    raw = "LGPL-2.1-or-later AND LGPL-2.1-or-later WITH GCC-exception-2.0 AND BSD-3-Clause"
    assert tokenize_license_string(raw) == [
        "LGPL-2.1-or-later",
        "LGPL-2.1-or-later WITH GCC-exception-2.0",
        "BSD-3-Clause",
    ]


def test_or_expression_splits_and_dedupes():
    assert tokenize_license_string("(MIT OR Apache-2.0) AND MIT") == ["MIT", "Apache-2.0"]


def test_comma_joined_and_plain_pass_through():
    assert tokenize_license_string("MIT, ISC") == ["MIT", "ISC"]
    assert tokenize_license_string("EPL-2.0") == ["EPL-2.0"]


def test_empty_falls_back_to_empty_list():
    assert tokenize_license_string("") == []
