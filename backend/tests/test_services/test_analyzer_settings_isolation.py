"""An analyzer binds the calling project's settings to itself, so the registry must not share one
instance across scans: two overlapping scans would otherwise persist each other's severities."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.core.constants import EOL_HIGH_AFTER_DAYS, EOL_MEDIUM_AFTER_DAYS
from app.models.finding import Severity
from tests.helpers.analyzers import build_analyzer

_EOL = "end_of_life"
_MAINTAINER_RISK = "maintainer_risk"
_PRODUCT = "isolated-product"
_DAYS_PAST_EOL = 60
_TIGHT_EOL = {"eol_high_after_days": 30, "eol_medium_after_days": 15}
_DEFAULT_EOL = {"eol_high_after_days": EOL_HIGH_AFTER_DAYS, "eol_medium_after_days": EOL_MEDIUM_AFTER_DAYS}
_SBOM = {"components": [{"name": _PRODUCT, "version": "1.0", "type": "library"}]}
_NO_COMPONENTS: dict[str, Any] = {"components": []}
_TIGHT_MAINTAINER = {"stale_after_days": 30, "warn_after_days": 15}
_DEFAULT_MAINTAINER: dict[str, Any] = {}
_DAYS_SINCE_RELEASE = 60
_NPM = "npm"
_STALE_PACKAGE = "stale_package"


@pytest.fixture
def _eol_cycle_in_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve the EOL cycle from cache, so the analyzer reaches its grading step without a fetch."""
    eol_date = (datetime.now(timezone.utc) - timedelta(days=_DAYS_PAST_EOL)).strftime("%Y-%m-%d")

    async def _mget(keys: list[str]) -> dict[str, Any]:
        # A cache round trip yields the loop; without that the two runs never interleave.
        await asyncio.sleep(0)
        return {key: [{"cycle": "1.0", "eol": eol_date}] for key in keys}

    monkeypatch.setattr("app.services.analyzers.end_of_life.cache_service.mget", _mget)


def _severities(result: dict[str, Any]) -> list[str]:
    return [issue["severity"] for issue in result["eol_issues"]]


def test_the_registry_hands_out_a_fresh_analyzer_per_resolution() -> None:
    assert build_analyzer(_EOL) is not build_analyzer(_EOL)


@pytest.mark.asyncio
async def test_two_projects_scanning_at_once_keep_their_own_eol_thresholds(_eol_cycle_in_cache: None) -> None:
    """60 days past EOL is HIGH under a 30-day threshold and LOW under the default 365-day one."""
    tight, default = await asyncio.gather(
        build_analyzer(_EOL).analyze(_SBOM, _TIGHT_EOL),
        build_analyzer(_EOL).analyze(_SBOM, _DEFAULT_EOL),
    )

    assert _severities(tight) == [Severity.HIGH.value]
    assert _severities(default) == [Severity.LOW.value]


@pytest.mark.asyncio
async def test_two_projects_scanning_at_once_keep_their_own_maintainer_thresholds() -> None:
    tight = build_analyzer(_MAINTAINER_RISK)
    default = build_analyzer(_MAINTAINER_RISK)

    await asyncio.gather(
        tight.analyze(_NO_COMPONENTS, _TIGHT_MAINTAINER),
        default.analyze(_NO_COMPONENTS, _DEFAULT_MAINTAINER),
    )

    info = {"days_since_release": _DAYS_SINCE_RELEASE}
    assert [risk["type"] for risk in tight._assess_risks(info, _NPM)] == [_STALE_PACKAGE]
    assert [risk["type"] for risk in default._assess_risks(info, _NPM)] == []
