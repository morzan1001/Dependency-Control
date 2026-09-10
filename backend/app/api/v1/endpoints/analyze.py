"""Stateless ad-hoc analysis: analyze a posted SBOM and return the result without storing it."""

import asyncio
import logging
from typing import Any

import redis.asyncio as redis
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError

from app.api.deps import AdhocKeyOrLegacyDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.body_limit import enforce_declared_body_size, read_body_within_limit
from app.api.v1.helpers.responses import RESP_AUTH_400
from app.core.config import settings
from app.core.constants import (
    ADHOC_DEADLINE_SECONDS,
    ADHOC_MAX_FINDINGS,
    ADHOC_RATE_LIMIT_PER_HOUR,
    ADHOC_RATE_LIMIT_PER_MINUTE,
    MAX_ADHOC_BODY_BYTES,
)
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse
from app.services.analysis.adhoc import ADHOC_SLOTS, AdhocInputTooLarge, run_adhoc_analysis
from app.services.analysis.adhoc_report import render_adhoc_html
from app.services.chat.rate_limiter import SURFACE_ADHOC, ChatRateLimiter

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_DEADLINE_EXCEEDED = "Analysis exceeded the {budget:.0f}s budget. Request fewer analyzers."
# A namespace of its own, so an ad-hoc caller and a chat user never share a window.
_RATE_LIMIT_PREFIX = "dc:adhoc:rl:"
_RATE_LIMITED = "Rate limit exceeded"
_HTML = "html"

_DESCRIPTION = f"""
Analyze posted SBOMs and scanner results and return findings, statistics, dependencies and
recommendations. Nothing is written: no scan, no findings, no dependency records, no audit row.

Storing nothing is not the same as sending nothing. Every run enriches vulnerability findings
through the EPSS API and the CISA KEV catalog, and the default analyzer set includes `osv`,
which sends the package coordinates read out of the posted SBOMs to `api.osv.dev`. Several
further analyzers reach a third party of their own once named. Pass an explicit `analyzers`
list to decide what leaves this process; `analyzers.notes` in the response names every stage
that did, and the host it reached.

Posted scanner output is validated entry by entry against the same models `/api/v1/ingest/*`
uses. A scanner whose entries do not validate is reported in `analyzers.errored` and contributes
no findings, so a report the pipeline could not read never reads as an all-clear.

At most {ADHOC_MAX_FINDINGS} findings are returned. Past that the set is cut by severity, and equally
severe findings are shared out over the finding types present so no one type can evict another.
`truncated` is null when the whole result is returned; otherwise it counts what was dropped, by
type and by severity, and `stats` describes only what came back.

`format: "html"` returns the same result as a standalone report document instead of JSON.
"""

_HTML_RESPONSE: dict[int | str, dict[str, Any]] = {200: {"content": {"text/html": {"schema": {"type": "string"}}}}}


def _parse_request(raw: bytes) -> AdhocAnalyzeRequest:
    """Validate the body here so the offending payload never reaches the traceback logger."""
    try:
        return AdhocAnalyzeRequest.model_validate_json(raw)
    except ValidationError as exc:
        detail = [{"loc": list(error["loc"]), "msg": error["msg"]} for error in exc.errors()]
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail) from exc


async def _enforce_rate_limit(owner_id: str) -> None:
    """Sliding window keyed on the token owner: a caller may mint as many keys as they like, and
    keying on any of them would let one budget be spent several times over. A Redis outage
    degrades to no limit rather than to no analysis."""
    try:
        async with redis.from_url(settings.REDIS_URL) as redis_client:
            limiter = ChatRateLimiter(redis_client, prefix=_RATE_LIMIT_PREFIX, surface=SURFACE_ADHOC)
            allowed, retry_after = await limiter.check_rate_limit(
                owner_id,
                per_minute=ADHOC_RATE_LIMIT_PER_MINUTE,
                per_hour=ADHOC_RATE_LIMIT_PER_HOUR,
            )
    except redis.RedisError:
        logger.warning("adhoc: Redis unavailable for rate limiting, allowing request")
        return

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_RATE_LIMITED,
            headers={"Retry-After": str(retry_after)},
        )


@router.post(
    "/analyze",
    response_model=AdhocAnalyzeResponse,
    responses={**RESP_AUTH_400, **_HTML_RESPONSE},
    summary="Analyze an SBOM without storing anything",
    description=_DESCRIPTION,
    dependencies=[Depends(enforce_declared_body_size(MAX_ADHOC_BODY_BYTES))],
)
async def analyze(
    request: Request,
    db: DatabaseDep,
    authenticated: AdhocKeyOrLegacyDep,
) -> Response:
    """Run the analysis pipeline in memory and return the result. Persists nothing."""
    _owner, key = authenticated
    await _enforce_rate_limit(key["user_id"])
    payload = _parse_request(await read_body_within_limit(request, MAX_ADHOC_BODY_BYTES))

    async def _run() -> AdhocAnalyzeResponse:
        async with ADHOC_SLOTS:
            return await run_adhoc_analysis(payload, db)

    try:
        result = await asyncio.wait_for(_run(), timeout=ADHOC_DEADLINE_SECONDS)
    except AdhocInputTooLarge as exc:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)) from exc
    except TimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=_DEADLINE_EXCEEDED.format(budget=ADHOC_DEADLINE_SECONDS),
        ) from exc

    if payload.format == _HTML:
        return HTMLResponse(content=render_adhoc_html(result))
    return JSONResponse(content=jsonable_encoder(result))
