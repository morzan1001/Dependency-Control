"""A numeric analyzer setting the analyzer cannot use is refused on write: stored, it fails or silently
disables that analyzer on every later scan of the project."""

import pytest
from pydantic import ValidationError

from app.schemas.project import ProjectCreate, ProjectUpdate


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"end_of_life": {"eol_high_after_days": "x"}}, id="eol-non-numeric"),
        pytest.param({"end_of_life": {"eol_high_after_days": None}}, id="eol-null"),
        pytest.param({"end_of_life": {"eol_high_after_days": True}}, id="eol-bool"),
        pytest.param({"end_of_life": {"eol_high_after_days": 365.5}}, id="eol-fractional-days"),
        pytest.param({"end_of_life": {"eol_high_after_days": 3651}}, id="eol-above-range"),
        pytest.param({"end_of_life": {"eol_medium_after_days": -1}}, id="eol-negative"),
        pytest.param({"end_of_life": {"eol_medium_after_days": 400}}, id="eol-medium-above-default-high"),
        pytest.param({"maintainer_risk": {"stale_after_days": 0}}, id="maintainer-zero"),
        pytest.param({"maintainer_risk": {"stale_after_days": "2y"}}, id="maintainer-non-numeric"),
        pytest.param(
            {"maintainer_risk": {"stale_after_days": 400, "warn_after_days": 500}}, id="maintainer-warn-above-stale"
        ),
        pytest.param({"typosquatting": {"similarity_threshold": 7}}, id="typo-percent"),
        pytest.param({"typosquatting": {"similarity_threshold": "0,85"}}, id="typo-comma-decimal"),
        pytest.param({"typosquatting": {"similarity_threshold": float("nan")}}, id="typo-nan"),
        pytest.param({"typosquatting": {"similarity_threshold": 0.92}}, id="typo-threshold-above-default-high"),
        pytest.param({"typosquatting": {"high_similarity": 0.97}}, id="typo-high-above-default-critical"),
        pytest.param({"deps_dev": {"scorecard_threshold": "abc"}}, id="scorecard-non-numeric"),
        pytest.param({"deps_dev": {"scorecard_threshold": 11}}, id="scorecard-above-range"),
    ],
)
def test_a_tunable_the_analyzer_cannot_use_is_refused(settings):
    with pytest.raises(ValidationError):
        ProjectUpdate(analyzer_settings=settings)
    with pytest.raises(ValidationError):
        ProjectCreate(name="p", analyzer_settings=settings)


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"end_of_life": {"eol_high_after_days": 0, "eol_medium_after_days": 0}}, id="eol-lower-edge"),
        pytest.param({"end_of_life": {"eol_high_after_days": 3650}}, id="eol-upper-edge"),
        pytest.param({"maintainer_risk": {"stale_after_days": 30, "warn_after_days": 30}}, id="maintainer-equal"),
        pytest.param({"typosquatting": {"similarity_threshold": 0.5}}, id="typo-lower-edge"),
        pytest.param(
            {"typosquatting": {"similarity_threshold": 0.9, "high_similarity": 0.95, "critical_similarity": 1}},
            id="typo-ladder-with-an-integer-one",
        ),
        pytest.param({"deps_dev": {"scorecard_threshold": 7}}, id="scorecard-integer"),
        pytest.param({"deps_dev": {"scorecard_threshold": 7.5}}, id="scorecard-fraction"),
        pytest.param({"end_of_life": {}}, id="nothing-set"),
        pytest.param({"trivy": {"anything": "goes"}}, id="analyzer-without-tunables"),
    ],
)
def test_a_usable_tunable_is_stored_as_written(settings):
    assert ProjectUpdate(analyzer_settings=settings).analyzer_settings == settings
