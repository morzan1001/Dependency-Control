"""Stateless ad-hoc analysis: analyze a posted SBOM and return the result without storing it."""

import asyncio
import logging

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.api.deps import AdhocKeyDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.body_limit import enforce_declared_body_size, read_body_within_limit
from app.api.v1.helpers.responses import RESP_AUTH_400
from app.core.constants import ADHOC_DEADLINE_SECONDS, MAX_ADHOC_BODY_BYTES
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse
from app.services.analysis.adhoc import ADHOC_SLOTS, AdhocInputTooLarge, run_adhoc_analysis

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_DEADLINE_EXCEEDED = "Analysis exceeded the {budget:.0f}s budget. Request fewer analyzers."

_DESCRIPTION = """
Analyze posted SBOMs and scanner results and return findings, statistics, dependencies and
recommendations. Nothing is written: no scan, no findings, no dependency records, no audit row.

Storing nothing is not the same as sending nothing. Every run enriches vulnerability findings
through the EPSS API and the CISA KEV catalog, and the default analyzer set includes `osv`,
which sends the package coordinates read out of the posted SBOMs to `api.osv.dev`. Pass an
explicit `analyzers` list to decide what leaves this process; `analyzers.notes` in the response
names every stage that did.
"""


def _parse_request(raw: bytes) -> AdhocAnalyzeRequest:
    """Validate the body here so the offending payload never reaches the traceback logger."""
    try:
        return AdhocAnalyzeRequest.model_validate_json(raw)
    except ValidationError as exc:
        detail = [{"loc": list(error["loc"]), "msg": error["msg"]} for error in exc.errors()]
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail) from exc


@router.post(
    "/analyze",
    response_model=AdhocAnalyzeResponse,
    responses=RESP_AUTH_400,
    summary="Analyze an SBOM without storing anything",
    description=_DESCRIPTION,
    dependencies=[Depends(enforce_declared_body_size(MAX_ADHOC_BODY_BYTES))],
)
async def analyze(
    request: Request,
    db: DatabaseDep,
    _key: AdhocKeyDep,
) -> Response:
    """Run the analysis pipeline in memory and return the result. Persists nothing."""
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

    return JSONResponse(content=jsonable_encoder(result))
