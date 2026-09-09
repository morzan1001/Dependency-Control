"""Crypto rules are evaluated in memory from the SBOM's embedded CBOM components."""

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase

_CRYPTO_RULES = "crypto_rules"
_NO_CRYPTO_ASSETS = "no cryptographic-asset components in the SBOM"
# The enrichment stage runs on every request and is reported last.
_ENRICHMENT = "epss_kev"

_SEED_POLICY = "shipped seed rules"

_CRYPTO_TYPE_PREFIX = "crypto_"
_TYPE_WEAK_KEY = "crypto_weak_key"
_TYPE_WEAK_ALGORITHM = "crypto_weak_algorithm"

_RSA_REF = "crypto/rsa-1024"
_AES_REF = "crypto/aes-256"
_MD5_REF = "crypto/md5"

# A seeded rule the certificate-lifecycle analyzer grades. It constrains nothing the matcher
# reads, so an unscoped evaluation would attribute it to every asset in the CBOM.
_CERTIFICATE_RULE = "cert-expiry-default"

_FIRST_SBOM_NAME = "first-service"
_SECOND_SBOM_SOURCE = "SBOM #2"

_RSA_1024 = {
    "type": "cryptographic-asset",
    "bom-ref": _RSA_REF,
    "name": "RSA",
    "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": "1024"},
    },
}

# Above every enabled key-size threshold the seeded policy sets for a block cipher.
_AES_256 = {
    "type": "cryptographic-asset",
    "bom-ref": _AES_REF,
    "name": "AES",
    "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "block-cipher", "parameterSetIdentifier": "256"},
    },
}

_MD5 = {
    "type": "cryptographic-asset",
    "bom-ref": _MD5_REF,
    "name": "MD5",
    "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
}

_LIBRARY_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        }
    ],
}


def _cbom(*components, metadata_name=None):
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)}
    if metadata_name:
        sbom["metadata"] = {"component": {"name": metadata_name}}
    return sbom


async def _run(sboms):
    request = AdhocAnalyzeRequest(sboms=sboms, analyzers=[], apply_global_waivers=False)
    return await run_adhoc_analysis(request, FakeDatabase())


def _crypto_findings(response):
    return [finding for finding in response.findings if str(finding["type"]).startswith(_CRYPTO_TYPE_PREFIX)]


def _matched_rule_ids(finding):
    return [entry["rule_id"] for entry in finding["details"]["matched_rules"]]


@pytest.mark.asyncio
async def test_a_weak_key_in_the_posted_cbom_becomes_a_finding():
    response = await _run([_cbom(_RSA_1024)])

    crypto = _crypto_findings(response)
    assert [finding["type"] for finding in crypto] == [_TYPE_WEAK_KEY]
    assert crypto[0]["details"]["bom_ref"] == _RSA_REF
    assert _CRYPTO_RULES in response.analyzers.ran


@pytest.mark.asyncio
async def test_the_same_cbom_twice_yields_the_same_finding_ids():
    """finding_id is how the response says findings are addressed, so it cannot be a per-run nonce.

    A random id makes two identical requests look like two different results, and no waiver
    written against one run can ever match the next.
    """
    first = _crypto_findings(await _run([_cbom(_RSA_1024, _MD5)]))
    second = _crypto_findings(await _run([_cbom(_RSA_1024, _MD5)]))

    assert [finding["id"] for finding in first] == [finding["id"] for finding in second]
    assert [finding["finding_id"] for finding in first] == [finding["id"] for finding in first]


@pytest.mark.asyncio
async def test_two_distinct_crypto_assets_keep_distinct_ids():
    """Stability must not be bought by collapsing different assets onto one id."""
    crypto = _crypto_findings(await _run([_cbom(_RSA_1024, _MD5)]))

    assert len({finding["id"] for finding in crypto}) == len(crypto) == 2


@pytest.mark.asyncio
async def test_a_rule_another_analyzer_grades_is_left_to_that_analyzer():
    response = await _run([_cbom(_RSA_1024, _AES_256)])

    crypto = _crypto_findings(response)
    # The compliant asset is the one a certificate rule would have blanketed.
    assert [finding["details"]["bom_ref"] for finding in crypto] == [_RSA_REF]
    assert _CERTIFICATE_RULE not in _matched_rule_ids(crypto[0])


@pytest.mark.asyncio
async def test_an_sbom_without_cryptographic_assets_reports_the_stage_as_skipped():
    response = await _run([_LIBRARY_SBOM])

    assert response.analyzers.skipped[_CRYPTO_RULES] == _NO_CRYPTO_ASSETS
    assert _CRYPTO_RULES not in response.analyzers.ran


@pytest.mark.asyncio
async def test_a_cbom_no_rule_matches_still_reports_the_stage_as_ran():
    """Coverage that found nothing is not the same as no coverage."""
    response = await _run([_cbom(_AES_256)])

    assert response.analyzers.ran == [_CRYPTO_RULES, _ENRICHMENT]
    assert _crypto_findings(response) == []
    assert _CRYPTO_RULES not in response.analyzers.skipped


@pytest.mark.asyncio
async def test_a_crypto_finding_names_the_sbom_it_was_read_from():
    response = await _run([_cbom(_MD5, metadata_name=_FIRST_SBOM_NAME), _cbom(_RSA_1024)])

    attribution = {finding["details"]["bom_ref"]: finding["found_in"] for finding in _crypto_findings(response)}
    assert attribution == {_MD5_REF: [_FIRST_SBOM_NAME], _RSA_REF: [_SECOND_SBOM_SOURCE]}


@pytest.mark.asyncio
async def test_the_response_says_which_policy_graded_the_assets():
    """The stage never reads the installation's crypto policy, so the result must not imply it did."""
    response = await _run([_cbom(_MD5)])

    assert _SEED_POLICY in response.analyzers.notes[_CRYPTO_RULES]


@pytest.mark.asyncio
async def test_a_cbom_the_stage_skipped_carries_no_policy_note():
    response = await _run([_cbom()])

    assert _CRYPTO_RULES not in response.analyzers.notes


@pytest.mark.asyncio
async def test_the_stage_reports_the_finding_type_each_rule_declares():
    response = await _run([_cbom(_MD5, _RSA_1024)])

    by_ref = {finding["details"]["bom_ref"]: finding["type"] for finding in _crypto_findings(response)}
    assert by_ref == {_MD5_REF: _TYPE_WEAK_ALGORITHM, _RSA_REF: _TYPE_WEAK_KEY}
