from datetime import datetime, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.cbom_parser import parse_cbom
from app.services.crypto_policy.seeder import load_seed_rules
from tests.helpers.analyzers import evaluate_crypto
from tests.helpers.cbom import content_ref


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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    expiring = [f for f in result["findings"] if f["type"] == "crypto_cert_expiring_soon"]
    if expected_severity is None:
        assert expiring == []
    else:
        assert len(expiring) == 1
        assert expiring[0]["severity"] == expected_severity


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "days_left,expected_severity",
    [
        (7, "CRITICAL"),
        (30, "HIGH"),
        (90, "MEDIUM"),
        (180, "LOW"),
    ],
)
async def test_a_cert_expiring_on_a_ladder_boundary_takes_that_rung(db, days_left, expected_severity):
    """The minutes of slack keep the floor division on the boundary day itself, which is the rung's own day."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(not_after=now + timedelta(days=days_left, minutes=5)),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    expiring = [f for f in result["findings"] if f["type"] == "crypto_cert_expiring_soon"]
    assert len(expiring) == 1
    assert expiring[0]["details"]["days_until_expiry"] == days_left
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
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
    sha1_rule = _weak_hash_rule(names=("SHA-1",)).model_copy(
        update={"rule_id": "ban-sha1", "default_severity": Severity.MEDIUM}
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), sha1_rule])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_signature"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "MEDIUM"
    assert weak[0]["details"]["rule_id"] == "ban-sha1"
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
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), _weak_key_rule(min_bits=2048)])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert len(weak) == 1


@pytest.mark.asyncio
async def test_weak_signing_key_does_not_flag_strong_subject_key(db):
    """A weak CA signing key with a strong subject key must not be flagged as a weak cert key."""
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
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), _weak_key_rule(min_bits=2048)])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
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
    """A policy 3072-bit minimum must flag a 2048-bit subject key that the static default would pass."""
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert len(weak) == 1


@pytest.mark.asyncio
async def test_key_exactly_at_the_policy_minimum_is_compliant(db):
    """A minimum is the smallest allowed size, so only a key below it is weak."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(bom_ref="c-at-minimum", not_after=now + timedelta(days=365), subject_key_ref="rsa3072"),
            _cert(bom_ref="c-below-minimum", not_after=now + timedelta(days=365), subject_key_ref="rsa3071"),
            _algo("rsa3072", "RSA", CryptoPrimitive.PKE, key_size=3072),
            _algo("rsa3071", "RSA", CryptoPrimitive.PKE, key_size=3071),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), _weak_key_rule(min_bits=3072)])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_key"]
    assert [f["details"]["bom_ref"] for f in weak] == ["c-below-minimum"]


@pytest.mark.asyncio
async def test_weak_signature_honors_glob_and_rule_severity(db):
    """A glob hash rule must match via fnmatch and the finding must use the rule's severity."""
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_signature"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "MEDIUM"  # rule severity, not hard-coded HIGH


@pytest.mark.asyncio
async def test_weak_signature_honors_policy_hash_ban(db):
    """A policy banning SHA-224 (outside the static MD5/SHA-1 set) must flag a SHA-224 signature."""
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    weak = [f for f in result["findings"] if f["type"] == "crypto_cert_weak_signature"]
    assert len(weak) == 1


@pytest.mark.asyncio
async def test_no_subject_key_ref_does_not_assert_weak_key(db):
    """Without a subject-key reference the analyzer must not assert a weak cert key from the signing algorithm."""
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
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), _weak_key_rule(min_bits=2048)])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    too_long = [f for f in result["findings"] if f["type"] == "crypto_cert_validity_too_long"]
    assert len(too_long) == 1


@pytest.mark.asyncio
async def test_validity_exactly_at_the_policy_limit_is_allowed(db):
    """398 days is the CA/Browser Forum maximum, so a cert issued at exactly that limit still complies."""
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _cert(
                bom_ref="c-at-limit",
                not_before=now - timedelta(days=10),
                not_after=now + timedelta(days=388),
            ),
            _cert(
                bom_ref="c-over-limit",
                not_before=now - timedelta(days=10),
                not_after=now + timedelta(days=389),
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
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    too_long = [f for f in result["findings"] if f["type"] == "crypto_cert_validity_too_long"]
    assert [f["details"]["validity_days"] for f in too_long] == [399]
    assert [f["details"]["bom_ref"] for f in too_long] == ["c-over-limit"]


@pytest.mark.asyncio
async def test_every_check_emits_only_declared_details_keys(db):
    """_build spreads **details into CryptoCertificateDetails, and the drift guard cannot
    see through a spread (blind spot 4 in its docstring), so assert it at runtime."""
    from app.schemas.finding_details import CryptoCertificateDetails

    now = datetime.now(timezone.utc)
    weak_hash = _algo("a-sha1", "SHA-1", CryptoPrimitive.HASH)
    weak_key = _algo("a-rsa", "RSA-1024", CryptoPrimitive.PKE, key_size=1024)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            weak_hash,
            weak_key,
            _cert(bom_ref="c-expired", not_after=now - timedelta(days=10)),
            _cert(bom_ref="c-expiring", not_after=now + timedelta(days=15)),
            _cert(bom_ref="c-future", not_before=now + timedelta(days=5), not_after=now + timedelta(days=90)),
            _cert(bom_ref="c-selfsigned", subject="CN=self", issuer="CN=self", not_after=now + timedelta(days=200)),
            _cert(bom_ref="c-weaksig", sig_algo_ref="a-sha1", not_after=now + timedelta(days=200)),
            _cert(bom_ref="c-weakkey", subject_key_ref="a-rsa", not_after=now + timedelta(days=200)),
            _cert(
                bom_ref="c-long",
                not_before=now - timedelta(days=10),
                not_after=now + timedelta(days=400),
            ),
        ],
    )
    validity_rule = CryptoRule(
        rule_id="validity-398",
        name="validity",
        description="",
        finding_type=FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG,
        default_severity=Severity.LOW,
        source=CryptoPolicySource.CUSTOM,
        validity_too_long_days=398,
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[_expiry_rule(), validity_rule, _weak_key_rule(), _weak_hash_rule(names=("SHA-1",))],
        )
    )

    result = await evaluate_crypto("crypto_certificate_lifecycle", db)

    emitted_types = {f["type"] for f in result["findings"]}
    assert len(emitted_types) >= 6, f"the fixture must exercise every check, got {sorted(emitted_types)}"
    declared = set(CryptoCertificateDetails.model_fields)
    undeclared = {key for f in result["findings"] for key in f["details"]} - declared
    assert not undeclared, f"undeclared details keys reach CryptoCertificateDetails: {sorted(undeclared)}"


def _cbom_component(bom_ref, name, asset_type, **properties):
    props_key = {
        "algorithm": "algorithmProperties",
        "certificate": "certificateProperties",
        "related-crypto-material": "relatedCryptoMaterialProperties",
    }[asset_type]
    return {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": name,
        "cryptoProperties": {"assetType": asset_type, props_key: properties},
    }


def _spec_cert_chain(now, signature, key_algorithm, key_size, key_algorithm_props=None):
    """A CycloneDX 1.6 certificate whose subject key is related-crypto-material pointing at its algorithm."""
    return [
        _cbom_component(
            "cert",
            "example.com",
            "certificate",
            subjectName="CN=example.com",
            issuerName="CN=Example CA",
            notValidBefore=(now - timedelta(days=30)).isoformat(),
            notValidAfter=(now + timedelta(days=300)).isoformat(),
            signatureAlgorithmRef="sig-algo",
            subjectPublicKeyRef="pubkey",
        ),
        _cbom_component("sig-algo", signature, "algorithm", primitive="signature"),
        _cbom_component(
            "pubkey", "public key", "related-crypto-material", type="public-key", size=key_size, algorithmRef="key-algo"
        ),
        _cbom_component("key-algo", key_algorithm, "algorithm", **(key_algorithm_props or {"primitive": "pke"})),
    ]


async def _analyze_spec_cbom(db, components, rules):
    assets = parse_cbom({"specVersion": "1.6", "components": components})
    await CryptoAssetRepository(db).bulk_upsert(
        "p", "s", [CryptoAsset(project_id="p", scan_id="s", **a.model_dump()) for a in assets]
    )
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=rules))
    return await evaluate_crypto("crypto_certificate_lifecycle", db)


@pytest.mark.asyncio
async def test_seeded_policy_judges_a_spec_shaped_certificate_by_its_rules(db):
    now = datetime.now(timezone.utc)
    chain = _spec_cert_chain(now, "SHA1withRSA", "RSA", 1024)
    result = await _analyze_spec_cbom(db, chain, load_seed_rules())
    by_type = {f["type"]: f for f in result["findings"]}
    assert set(by_type) == {"crypto_cert_weak_signature", "crypto_cert_weak_key"}
    weak_sig = by_type["crypto_cert_weak_signature"]
    assert (weak_sig["severity"], weak_sig["details"]["rule_id"]) == ("MEDIUM", "nist-131a-sha1")
    weak_key = by_type["crypto_cert_weak_key"]
    assert (weak_key["severity"], weak_key["details"]["rule_id"]) == ("HIGH", "nist-131a-rsa-min-2048")
    assert (weak_key["details"]["key_size_bits"], weak_key["details"]["min_key_size_bits"]) == (1024, 2048)
    assert weak_key["details"]["related_algo_bom_ref"] == content_ref(chain[3])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "signature,key_algorithm,key_size,key_props",
    [
        ("SHA256withECDSA", "ECDSA-P256", 256, {"primitive": "signature", "curve": "P-256"}),
        ("SHA384withECDSA", "ECDSA-P384", 384, {"primitive": "signature", "curve": "P-384"}),
        ("Ed25519", "Ed25519", 256, {"primitive": "signature", "curve": "Ed25519"}),
    ],
)
async def test_seeded_policy_leaves_modern_ec_certificates_alone(db, signature, key_algorithm, key_size, key_props):
    now = datetime.now(timezone.utc)
    components = _spec_cert_chain(now, signature, key_algorithm, key_size, key_props)
    result = await _analyze_spec_cbom(db, components, load_seed_rules())
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_disabling_the_seeded_rules_silences_weak_signature_and_weak_key(db):
    now = datetime.now(timezone.utc)
    silenced = {"nist-131a-sha1", "nist-131a-rsa-min-2048"}
    rules = [r.model_copy(update={"enabled": False}) if r.rule_id in silenced else r for r in load_seed_rules()]
    result = await _analyze_spec_cbom(db, _spec_cert_chain(now, "SHA1withRSA", "RSA", 1024), rules)
    assert result["findings"] == []


def _type_rule(rule_id, finding_type, severity=Severity.HIGH, enabled=True, **fields):
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=finding_type,
        default_severity=severity,
        source=CryptoPolicySource.CUSTOM,
        enabled=enabled,
        **fields,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "finding_type,cert_kwargs",
    [
        (FindingType.CRYPTO_CERT_EXPIRED, {"not_after_days": -10}),
        (FindingType.CRYPTO_CERT_NOT_YET_VALID, {"not_before_days": 5}),
        (FindingType.CRYPTO_CERT_SELF_SIGNED, {"issuer": "CN=example.com"}),
    ],
)
@pytest.mark.parametrize("enabled,expected", [(True, ["HIGH"]), (False, [])])
async def test_a_policy_rule_of_the_check_type_sets_its_severity_or_disables_it(
    db, finding_type, cert_kwargs, enabled, expected
):
    now = datetime.now(timezone.utc)
    cert = _cert(
        issuer=cert_kwargs.get("issuer", "CN=Example CA"),
        not_before=now + timedelta(days=cert_kwargs.get("not_before_days", -1)),
        not_after=now + timedelta(days=cert_kwargs.get("not_after_days", 365)),
    )
    await CryptoAssetRepository(db).bulk_upsert("p", "s", [cert])
    rule = _type_rule("team-cert-check", finding_type, enabled=enabled)
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[rule]))
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    assert [f["severity"] for f in result["findings"] if f["type"] == finding_type.value] == expected


@pytest.mark.asyncio
async def test_overlapping_expiry_rules_emit_one_finding_at_the_strictest_rung(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert("p", "s", [_cert(not_after=now + timedelta(days=20, minutes=5))])
    strict = _type_rule(
        "team-expiry-strict",
        FindingType.CRYPTO_CERT_EXPIRING_SOON,
        expiry_critical_days=30,
        expiry_high_days=60,
    )
    stray = _type_rule("stray-weak-key", FindingType.CRYPTO_WEAK_KEY, match_primitive=CryptoPrimitive.PKE)
    stray = stray.model_copy(update={"expiry_critical_days": 365})
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule(), strict, stray])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    expiring = [f for f in result["findings"] if f["type"] == "crypto_cert_expiring_soon"]
    assert len(expiring) == 1
    assert expiring[0]["severity"] == "CRITICAL"
    details = expiring[0]["details"]
    assert details["rule_id"] == "team-expiry-strict"
    assert {(m["rule_id"], m["severity"]) for m in details["matched_rules"]} == {
        ("team-expiry-strict", "CRITICAL"),
        ("cert-expiry-default", "HIGH"),
    }
    assert "threshold_matched" not in details


@pytest.mark.asyncio
async def test_overlapping_validity_rules_emit_one_finding_for_the_strictest_rule(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p", "s", [_cert(not_before=now - timedelta(days=10), not_after=now + timedelta(days=400))]
    )
    rules = [
        _type_rule("validity-398", FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG, Severity.LOW, validity_too_long_days=398),
        _type_rule(
            "validity-200", FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG, Severity.MEDIUM, validity_too_long_days=200
        ),
    ]
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=rules))
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    too_long = [f for f in result["findings"] if f["type"] == "crypto_cert_validity_too_long"]
    assert len(too_long) == 1
    assert too_long[0]["severity"] == "MEDIUM"
    assert (too_long[0]["details"]["rule_id"], too_long[0]["details"]["threshold"]) == ("validity-200", 200)
    assert {m["rule_id"] for m in too_long[0]["details"]["matched_rules"]} == {"validity-398", "validity-200"}


@pytest.mark.asyncio
async def test_certificate_finding_ids_are_stable_across_runs(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert("p", "s", [_cert(not_after=now - timedelta(days=10))])
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    first = await evaluate_crypto("crypto_certificate_lifecycle", db)
    second = await evaluate_crypto("crypto_certificate_lifecycle", db)
    assert [f["id"] for f in first["findings"]] == ["CRYPTO-crypto_cert_expired-c1"]
    assert [f["id"] for f in second["findings"]] == [f["id"] for f in first["findings"]]


@pytest.mark.asyncio
async def test_self_signed_details_carry_no_duplicate_subject_and_issuer(db):
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p", "s", [_cert(subject="CN=self", issuer="CN=self", not_after=now + timedelta(days=200))]
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[_expiry_rule()])
    )
    result = await evaluate_crypto("crypto_certificate_lifecycle", db)
    (finding,) = result["findings"]
    assert finding["details"] == {
        "bom_ref": "c1",
        "subject_name": "CN=self",
        "issuer_name": "CN=self",
        "occurrence_count": 0,
    }


@pytest.mark.asyncio
async def test_a_certificate_finding_carries_the_first_twenty_locations_and_the_total(db):
    now = datetime.now(timezone.utc)
    (cert, *rest) = _spec_cert_chain(now, "SHA1withRSA", "RSA", 1024)
    cert["evidence"] = {"occurrences": [{"location": f"src/Crypto{index}.java", "line": index} for index in range(25)]}
    result = await _analyze_spec_cbom(db, [cert, *rest], load_seed_rules())
    assert result["findings"]
    for finding in result["findings"]:
        assert finding["found_in"] == [f"src/Crypto{index}.java" for index in range(20)]
        assert finding["details"]["occurrence_count"] == 25
