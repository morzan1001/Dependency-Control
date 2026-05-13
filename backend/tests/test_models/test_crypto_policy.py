from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule


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
