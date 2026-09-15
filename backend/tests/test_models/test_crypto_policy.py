import pytest
from pydantic import ValidationError

from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule


def _quantum_rule(**overrides):
    kwargs = {
        "rule_id": "pqc-rsa",
        "name": "RSA is quantum vulnerable",
        "description": "Shor's algorithm breaks RSA",
        "finding_type": FindingType.CRYPTO_QUANTUM_VULNERABLE,
        "default_severity": Severity.MEDIUM,
        "source": CryptoPolicySource.NIST_PQC,
        "quantum_vulnerable": True,
    }
    kwargs.update(overrides)
    return CryptoRule(**kwargs)


def test_crypto_rule_minimal():
    r = CryptoRule(
        rule_id="weak-algo-md5",
        name="MD5 is cryptographically broken",
        description="MD5 should not be used for cryptographic purposes",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        match_name_patterns=["MD5", "md5"],
        source=CryptoPolicySource.NIST_SP_800_131A,
    )
    assert r.enabled is True
    assert r.rule_id == "weak-algo-md5"


def test_quantum_vulnerable_rule_without_name_patterns_is_rejected():
    with pytest.raises(ValidationError, match="match_name_patterns"):
        _quantum_rule(match_name_patterns=[])


def test_quantum_vulnerable_rule_with_name_patterns_is_accepted():
    rule = _quantum_rule(match_name_patterns=["RSA", "ECDSA"])
    assert rule.quantum_vulnerable is True


def test_rule_marked_not_quantum_vulnerable_needs_no_name_patterns():
    rule = _quantum_rule(quantum_vulnerable=False, match_curves=["secp256k1"], match_name_patterns=[])
    assert rule.quantum_vulnerable is False


def test_crypto_policy_system_scope():
    p = CryptoPolicy(
        scope="system",
        rules=[],
        version=1,
    )
    assert p.scope == "system"
    assert p.project_id is None


def test_crypto_policy_project_scope_requires_project_id():
    p = CryptoPolicy(
        scope="project",
        project_id="abc",
        rules=[],
        version=1,
    )
    assert p.project_id == "abc"
