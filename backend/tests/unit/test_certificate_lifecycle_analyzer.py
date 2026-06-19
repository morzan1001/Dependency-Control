from datetime import datetime, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.certificate_lifecycle import (
    CertificateLifecycleAnalyzer,
)


def _cert(
    bom_ref="c1",
    subject="CN=example.com",
    issuer="CN=Example CA",
    not_before=None,
    not_after=None,
    sig_algo_ref=None,
    subject_key_ref=None,
):
    return CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref=bom_ref,
        name=subject,
        asset_type=CryptoAssetType.CERTIFICATE,
        subject_name=subject,
        issuer_name=issuer,
        not_valid_before=not_before,
        not_valid_after=not_after,
        signature_algorithm_ref=sig_algo_ref,
        subject_public_key_ref=subject_key_ref,
    )


def _algo(bom_ref, name, primitive, key_size=None):
    return CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
        key_size_bits=key_size,
    )


def _expiry_rule():
    return CryptoRule(
        rule_id="cert-expiry-default",
        name="expiry",
        description="",
        finding_type=FindingType.CRYPTO_CERT_EXPIRING_SOON,
        default_severity=Severity.MEDIUM,
        source=CryptoPolicySource.CUSTOM,
        expiry_critical_days=7,
        expiry_high_days=30,
        expiry_medium_days=90,
        expiry_low_days=180,
    )


@pytest.mark.asyncio
async def test_expired_cert_emits_critical(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now - timedelta(days=10)),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    expired = [f for f in result["findings"] if f["type"] == "crypto_cert_expired"]
    assert len(expired) == 1
    assert expired[0]["severity"] == "CRITICAL"
    assert expired[0]["details"]["days_expired"] == 10


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "days_left,expected_severity",
    [
        (3, "CRITICAL"),
        (7, "CRITICAL"),
        (15, "HIGH"),
        (30, "HIGH"),
        (60, "MEDIUM"),
        (90, "MEDIUM"),
        (120, "LOW"),
        (180, "LOW"),
        (365, None),
    ],
)
async def test_expiring_cert_severity_ladder(db, days_left, expected_severity):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=days_left)),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    expiring = [f for f in result["findings"] if f["type"] == "crypto_cert_expiring_soon"]
    if expected_severity is None:
        assert expiring == []
    else:
        assert len(expiring) == 1
        assert expiring[0]["severity"] == expected_severity


@pytest.mark.asyncio
async def test_not_yet_valid_cert_emits_low(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_before=now + timedelta(days=5), not_after=now + timedelta(days=365)),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    nyv = [f for f in result["findings"] if f["type"] == "crypto_cert_not_yet_valid"]
    assert len(nyv) == 1
    assert nyv[0]["severity"] == "LOW"


@pytest.mark.asyncio
async def test_self_signed_detected(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(subject="CN=self", issuer="CN=self", not_after=now + timedelta(days=400)),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    selfs = [f for f in result["findings"] if f["type"] == "crypto_cert_self_signed"]
    assert len(selfs) == 1
    assert selfs[0]["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_weak_signature_resolved_via_ref(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), sig_algo_ref="sha1-algo"),
            _algo("sha1-algo", "SHA-1", CryptoPrimitive.HASH),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_signature"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "HIGH"
    assert weak[0]["details"]["related_algo_bom_ref"] == "sha1-algo"


@pytest.mark.asyncio
async def test_weak_key_uses_subject_public_key(db):
    """The weak-key verdict must judge the certificate's OWN subject public key."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), subject_key_ref="subjkey"),
            _algo("subjkey", "RSA", CryptoPrimitive.PKE, key_size=1024),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(sbom={}, project_id="p", scan_id="s", db=db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert len(weak) == 1


@pytest.mark.asyncio
async def test_weak_signing_key_does_not_flag_strong_subject_key(db):
    """A weak SIGNING key (CA) with a strong subject key must NOT be flagged as a
    weak certificate key — that was the bug: judging the cert from the CA's key."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), sig_algo_ref="rsa1024", subject_key_ref="rsa4096"),
            _algo("rsa1024", "RSA", CryptoPrimitive.PKE, key_size=1024),
            _algo("rsa4096", "RSA", CryptoPrimitive.PKE, key_size=4096),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(sbom={}, project_id="p", scan_id="s", db=db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert len(weak) == 0


def _weak_key_rule(min_bits=3072):
    return CryptoRule(
        rule_id="cnsa-rsa-min",
        name="rsa-min",
        description="",
        finding_type=FindingType.CRYPTO_WEAK_KEY,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
        match_primitive=CryptoPrimitive.PKE,
        match_name_patterns=["RSA"],
        match_min_key_size_bits=min_bits,
    )


def _weak_hash_rule(names=("SHA-224",)):
    return CryptoRule(
        rule_id="ban-sha224",
        name="sha224",
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
        match_primitive=CryptoPrimitive.HASH,
        match_name_patterns=list(names),
    )


@pytest.mark.asyncio
async def test_weak_key_honors_policy_min_size(db):
    """A CNSA-style 3072-bit minimum must flag a 2048-bit subject key that the
    static 2048 default would pass — i.e. the policy is honored (audit #10)."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), subject_key_ref="rsa2048"),
            _algo("rsa2048", "RSA", CryptoPrimitive.PKE, key_size=2048),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), _weak_key_rule(min_bits=3072)])
    )
    result = await CertificateLifecycleAnalyzer().analyze(sbom={}, project_id="p", scan_id="s", db=db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert len(weak) == 1


@pytest.mark.asyncio
async def test_weak_signature_honors_glob_and_rule_severity(db):
    """A policy hash rule with a GLOB pattern must match (canonical fnmatch
    semantics, audit MF5), and the finding must use the RULE's severity, not a
    hard-coded HIGH (audit SC#5)."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), sig_algo_ref="sha224"),
            _algo("sha224", "SHA-224", CryptoPrimitive.HASH),
        ],
    )
    glob_rule = CryptoRule(
        rule_id="ban-sha2-short",
        name="sha2-short",
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.MEDIUM,
        source=CryptoPolicySource.CUSTOM,
        match_primitive=CryptoPrimitive.HASH,
        match_name_patterns=["SHA-2*"],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), glob_rule])
    )
    result = await CertificateLifecycleAnalyzer().analyze(sbom={}, project_id="p", scan_id="s", db=db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_signature"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "MEDIUM"  # rule severity, not hard-coded HIGH


@pytest.mark.asyncio
async def test_weak_signature_honors_policy_hash_ban(db):
    """A policy banning SHA-224 (not in the static MD5/SHA-1 set) must flag a
    SHA-224 signature (audit #10)."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), sig_algo_ref="sha224"),
            _algo("sha224", "SHA-224", CryptoPrimitive.HASH),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), _weak_hash_rule(["SHA-224"])])
    )
    result = await CertificateLifecycleAnalyzer().analyze(sbom={}, project_id="p", scan_id="s", db=db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_signature"]
    assert len(weak) == 1


@pytest.mark.asyncio
async def test_no_subject_key_ref_does_not_assert_weak_key(db):
    """Without a subject-key reference the analyzer must not assert a weak cert key
    from the signing algorithm."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=365), sig_algo_ref="rsa1024"),
            _algo("rsa1024", "RSA", CryptoPrimitive.PKE, key_size=1024),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await CertificateLifecycleAnalyzer().analyze(sbom={}, project_id="p", scan_id="s", db=db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert len(weak) == 0


@pytest.mark.asyncio
async def test_validity_too_long(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(
                not_before=now - timedelta(days=10),
                not_after=now + timedelta(days=400),
            ),
        ],
    )
    rule = CryptoRule(
        rule_id="validity-398",
        name="validity",
        description="",
        finding_type=FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG,
        default_severity=Severity.LOW,
        source=CryptoPolicySource.CUSTOM,
        validity_too_long_days=398,
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), rule])
    )
    result = await CertificateLifecycleAnalyzer().analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    too_long = [f for f in result["findings"] if f["type"] == "crypto_cert_validity_too_long"]
    assert len(too_long) == 1
