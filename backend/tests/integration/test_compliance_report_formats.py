"""Format-coverage tests for the compliance report pipeline across text formats."""

import asyncio

import pytest

from tests.conftest import WEASYPRINT_USABLE

_POLL_ATTEMPTS = 50
_PDF_POLL_ATTEMPTS = 100
_POLL_INTERVAL_SECONDS = 0.1
_TERMINAL_STATUSES = ("completed", "failed")


async def _poll_until_terminal(client, report_id, headers, attempts=_POLL_ATTEMPTS):
    for _ in range(attempts):
        resp = await client.get(f"/api/v1/compliance/reports/{report_id}", headers=headers)
        assert resp.status_code == 200, resp.text
        if resp.json()["status"] in _TERMINAL_STATUSES:
            return resp
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
    raise AssertionError(f"report {report_id} never reached a terminal status")


def _install_fake_pipeline(monkeypatch):
    """Common monkeypatch setup: fake gather_inputs + fake GridFS store."""
    from unittest.mock import AsyncMock

    from app.api.v1.endpoints import compliance_reports as ep_mod
    from app.services.analytics.scopes import ResolvedScope
    from app.services.compliance import engine as engine_mod
    from app.services.compliance.frameworks.base import EvaluationInput

    inputs = EvaluationInput(
        resolved=ResolvedScope(scope="project", scope_id="p", project_ids=["p"]),
        scope_description="project 'p'",
        crypto_assets=[],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=[],
    )
    monkeypatch.setattr(
        engine_mod.ComplianceReportEngine,
        "_gather_inputs",
        AsyncMock(return_value=inputs),
    )

    store: dict = {}

    async def _fake_store(self, db_, artifact_bytes, filename, mime_type):
        # Mirror production: GridFS returns an ObjectId that the engine serialises to its string form before persisting.
        from bson import ObjectId

        key = str(ObjectId())
        store[key] = {"bytes": artifact_bytes, "mime": mime_type, "filename": filename}
        return key

    monkeypatch.setattr(
        engine_mod.ComplianceReportEngine,
        "_store_artifact",
        _fake_store,
    )

    class _FakeStream:
        def __init__(self, data: bytes):
            self._data = data
            self._done = False

        async def readchunk(self) -> bytes:
            if self._done:
                return b""
            self._done = True
            return self._data

        async def close(self):
            return None

    class _FakeBucket:
        def __init__(self, _db):
            pass

        async def open_download_stream(self, gid):
            entry = store.get(str(gid))
            if entry is None:
                raise RuntimeError("not found")
            return _FakeStream(entry["bytes"])

        async def delete(self, _gid):
            return None

    monkeypatch.setattr(ep_mod, "AsyncIOMotorGridFSBucket", _FakeBucket)

    return store


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fmt,mime",
    [
        ("json", "application/json"),
        ("csv", "text/csv"),
        ("sarif", "application/sarif+json"),
    ],
)
async def test_each_format_renders(
    client,
    db,
    owner_auth_headers_proj,
    fmt,
    mime,
    monkeypatch,
):
    _install_fake_pipeline(monkeypatch)

    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p", "framework": "nist-sp-800-131a", "format": fmt},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    report_id = resp.json()["report_id"]

    g = await _poll_until_terminal(client, report_id, owner_auth_headers_proj)
    assert g.json()["status"] == "completed", g.json()

    dl = await client.get(
        f"/api/v1/compliance/reports/{report_id}/download",
        headers=owner_auth_headers_proj,
    )
    assert dl.status_code == 200, dl.text
    # FastAPI/Starlette may append "; charset=utf-8" to text MIME types.
    assert dl.headers.get("content-type", "").startswith(mime)
    assert len(dl.content) > 0


@pytest.mark.skipif(not WEASYPRINT_USABLE, reason="WeasyPrint not installed or native libs missing")
@pytest.mark.asyncio
async def test_pdf_format_if_weasyprint_available(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    _install_fake_pipeline(monkeypatch)

    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p", "framework": "nist-sp-800-131a", "format": "pdf"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    report_id = resp.json()["report_id"]

    g = await _poll_until_terminal(client, report_id, owner_auth_headers_proj, attempts=_PDF_POLL_ATTEMPTS)
    assert g.json()["status"] == "completed", g.json()

    dl = await client.get(
        f"/api/v1/compliance/reports/{report_id}/download",
        headers=owner_auth_headers_proj,
    )
    assert dl.headers.get("content-type") == "application/pdf"
    assert dl.content[:4] == b"%PDF"
