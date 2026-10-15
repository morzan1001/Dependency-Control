import time
from datetime import datetime, timedelta, timezone
from functools import partial

import httpx
import pytest

from app.services.github import GitHubService
from tests.mocks.github import make_github_instance

_SECONDARY_LIMIT = {
    "message": "You have exceeded a secondary rate limit. Please wait a few minutes before you try again."
}


def _serve(monkeypatch, *answers: httpx.Response) -> list[httpx.Request]:
    queue = list(answers)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return queue.pop(0)

    monkeypatch.setattr(httpx, "AsyncClient", partial(httpx.AsyncClient, transport=httpx.MockTransport(handler)))
    return seen


def _service() -> GitHubService:
    return GitHubService(make_github_instance(access_token="ghp-secret"))


@pytest.mark.asyncio
async def test_a_secondary_limit_holds_until_its_retry_after(monkeypatch):
    """It leaves the core budget standing, so the refusal's own Retry-After is all that names it."""
    _serve(
        monkeypatch,
        httpx.Response(403, headers={"Retry-After": "120", "X-RateLimit-Remaining": "4990"}, json=_SECONDARY_LIMIT),
    )
    service = _service()
    asked_at = datetime.now(timezone.utc)

    assert await service.get_viewer_organisations() is None

    assert service.rate_limited_until is not None
    lifts_in = service.rate_limited_until - asked_at
    assert timedelta(seconds=119) <= lifts_in <= timedelta(seconds=121)


@pytest.mark.asyncio
async def test_a_spent_quota_holds_until_its_reset(monkeypatch):
    reset = int(time.time()) + 600
    _serve(monkeypatch, httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)}))
    service = _service()

    assert await service.get_current_user_id() is None

    assert service.rate_limited_until == datetime.fromtimestamp(reset, tz=timezone.utc)


@pytest.mark.asyncio
async def test_a_refusal_without_rate_limit_headers_is_no_rate_limit(monkeypatch):
    _serve(monkeypatch, httpx.Response(403, json={"message": "Resource not accessible by personal access token"}))
    service = _service()

    assert await service.get_viewer_organisations() is None

    assert service.rate_limited_until is None


@pytest.mark.asyncio
async def test_nothing_is_sent_before_the_retry_after_has_run(monkeypatch):
    """GitHub may ban an integration that keeps sending while it is rate limited."""
    seen = _serve(monkeypatch, httpx.Response(429, headers={"Retry-After": "60"}, json=_SECONDARY_LIMIT))
    service = _service()

    await service.get_viewer_organisations()

    assert await service.count_org_teams("acme") is None
    assert await service.get_current_user_id() is None
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_every_service_of_the_instance_waits_out_the_retry_after(monkeypatch):
    """Branch sync builds a service per project, so a hold one service kept to itself would not stop the next."""
    seen = _serve(monkeypatch, httpx.Response(429, headers={"Retry-After": "60"}, json=_SECONDARY_LIMIT))

    await _service().get_viewer_organisations()

    assert await _service().list_branches("acme", "api") is None
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_a_shorter_refusal_does_not_cut_a_longer_hold_short():
    """Requests already in flight when the quota ran out answer in any order."""
    reset = int(time.time()) + 600
    spent, throttled = _service(), _service()

    await spent._note_rate_limit(
        httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)})
    )
    await throttled._note_rate_limit(httpx.Response(429, headers={"Retry-After": "60"}))

    assert spent.rate_limited_until == datetime.fromtimestamp(reset, tz=timezone.utc)


@pytest.mark.asyncio
async def test_a_hold_whose_time_has_passed_is_no_rate_limit(monkeypatch):
    """A connection test long after the refusal must not still blame the rate limit."""
    _serve(monkeypatch, httpx.Response(429, headers={"Retry-After": "0"}, json=_SECONDARY_LIMIT))
    service = _service()

    await service.get_viewer_organisations()

    assert service.rate_limited_until is None
