"""Registry fan-out is one bounded gather: at most ``limit`` lookups in flight and no idle pauses."""

import asyncio

import pytest

from app.core.constants import ANALYZER_BATCH_SIZES
from app.services.analyzers.base import gather_bounded
from app.services.analyzers.maintainer_risk import MaintainerRiskAnalyzer
from app.services.analyzers.malware import OpenSourceMalwareAnalyzer

_LIMIT = 3
_ITEMS = 10


@pytest.mark.asyncio
async def test_at_most_limit_workers_run_at_once_and_results_keep_their_order():
    live = peak = 0

    async def worker(item: int) -> int:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return item * 2

    results = await gather_bounded(range(_ITEMS), worker, _LIMIT)

    assert results == [item * 2 for item in range(_ITEMS)]
    assert peak == _LIMIT


@pytest.mark.asyncio
async def test_a_failing_worker_leaves_its_exception_in_its_slot():
    async def worker(item: int) -> int:
        if item == 1:
            raise ValueError("boom")
        return item

    results = await gather_bounded([0, 1, 2], worker, _LIMIT)

    assert results[0] == 0
    assert isinstance(results[1], ValueError)
    assert results[2] == 2


def _components_without_a_registry(count: int) -> list[dict[str, str]]:
    return [
        {"name": f"pkg{index}", "version": "1.0.0", "purl": f"pkg:generic/pkg{index}@1.0.0"} for index in range(count)
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("analyzer", "batch_key", "settings"),
    [
        pytest.param(MaintainerRiskAnalyzer(), "maintainer_risk", {}, id="maintainer_risk"),
        pytest.param(OpenSourceMalwareAnalyzer(), "malware", {"open_source_malware_api_key": "k"}, id="os_malware"),
    ],
)
async def test_a_run_that_makes_no_request_never_pauses(monkeypatch, analyzer, batch_key, settings):
    pauses: list[float] = []

    async def record_pause(delay: float, *_args, **_kwargs) -> None:
        pauses.append(delay)

    monkeypatch.setattr(asyncio, "sleep", record_pause)
    components = _components_without_a_registry(ANALYZER_BATCH_SIZES[batch_key] * 2 + 1)

    await analyzer.analyze({}, settings, components)

    assert pauses == []
