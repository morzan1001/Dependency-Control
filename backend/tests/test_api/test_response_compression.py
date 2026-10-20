import httpx
import pytest
from fastapi import FastAPI, Response
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware

from app.main import app

_BODY = b"%PDF-1.7 " + b"0" * 4000


def _gzip_options() -> dict:
    (registered,) = [m for m in app.user_middleware if m.cls is GZipMiddleware]
    return registered.kwargs


def _probe() -> FastAPI:
    probe = FastAPI(middleware=[Middleware(GZipMiddleware, **_gzip_options())])

    @probe.get("/report.pdf")
    async def pdf() -> Response:
        return Response(_BODY, media_type="application/pdf")

    @probe.get("/report.csv")
    async def csv() -> Response:
        return Response(_BODY, media_type="text/csv")

    return probe


async def _encoding(path: str) -> str | None:
    transport = httpx.ASGITransport(app=_probe())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(path, headers={"Accept-Encoding": "gzip"})
    assert response.content == _BODY
    return response.headers.get("content-encoding")


@pytest.mark.asyncio
async def test_an_already_compressed_pdf_is_sent_as_it_is():
    assert await _encoding("/report.pdf") is None


@pytest.mark.asyncio
async def test_a_text_report_is_still_gzipped():
    assert await _encoding("/report.csv") == "gzip"


def test_responses_are_compressed_at_the_cheaper_default_level():
    assert _gzip_options()["compresslevel"] == 6
