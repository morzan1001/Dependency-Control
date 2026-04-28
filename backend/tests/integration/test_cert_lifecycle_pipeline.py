"""
Integration: registry-resolved CertificateLifecycleAnalyzer produces findings.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analysis.registry import analyzers


@pytest.mark.asyncio
async def test_cert_lifecycle_registered_and_runs(db):
    analyzer = analyzers["crypto_certificate_lifecycle"]
    now = datetime.now(timezone.utc)
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            CryptoAsset(
                project_id="p",
                scan_id="s",
                bom_ref="c1",
                name="CN=internal",
                asset_type=CryptoAssetType.CERTIFICATE,
                subject_name="CN=internal",
                issuer_name="CN=internal",
                not_valid_before=now - timedelta(days=5),
                not_valid_after=now + timedelta(days=5),
            ),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[
                CryptoRule(
                    rule_id="exp",
                    name="exp",
                    description="",
                    finding_type=FindingType.CRYPTO_CERT_EXPIRING_SOON,
                    default_severity=Severity.MEDIUM,
                    source=CryptoPolicySource.CUSTOM,
                    expiry_critical_days=7,
                    expiry_high_days=30,
                )
            ],
        )
    )

    result = await analyzer.analyze(
        sbom={},
        project_id="p",
        scan_id="s",
        db=db,
    )
    types = {f["type"] for f in result["findings"]}
    assert "crypto_cert_expiring_soon" in types
    assert "crypto_cert_self_signed" in types
