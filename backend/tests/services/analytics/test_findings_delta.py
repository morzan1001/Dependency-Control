from app.services.analytics.findings_delta import finding_identity_key


def test_identity_key_vulnerability_uses_cve_id():
    f = {
        "type": "vulnerability",
        "component": "log4j-core@2.17.1",
        "details": {"cve_id": "CVE-2025-1234"},
    }
    assert finding_identity_key(f) == ("vulnerability", "log4j-core@2.17.1", "CVE-2025-1234")


def test_identity_key_secret_uses_pattern_hash():
    f = {
        "type": "secret",
        "component": "src/api/keys.py",
        "details": {"pattern_hash": "abc123"},
    }
    assert finding_identity_key(f) == ("secret", "src/api/keys.py", "abc123")


def test_identity_key_sast_uses_rule_id():
    f = {
        "type": "sast",
        "component": "src/api/keys.py",
        "details": {"rule_id": "py/sql-injection", "line": 42},
    }
    assert finding_identity_key(f) == ("sast", "src/api/keys.py", "py/sql-injection:42")


def test_identity_key_license_uses_license_id():
    f = {
        "type": "license",
        "component": "lodash@4.17.21",
        "details": {"license_id": "GPL-3.0"},
    }
    assert finding_identity_key(f) == ("license", "lodash@4.17.21", "GPL-3.0")


def test_identity_key_unknown_falls_back_to_full_fingerprint():
    f = {
        "type": "other",
        "component": "x",
        "details": {},
        "description": "weird thing",
    }
    key = finding_identity_key(f)
    assert key[0] == "other"
    assert key[1] == "x"
    assert key[2] != ""  # some fallback identifier present
