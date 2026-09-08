"""A license policy that is not what the caller wrote is worse than a rejected one: it is stored on
the project and re-applied to every future scan, and the only symptom is a severity that moved."""

import pytest
from pydantic import ValidationError

from app.models.license import DeploymentModel
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.schemas.project import LicensePolicySchema, ProjectCreate, ProjectUpdate


@pytest.mark.parametrize("typo", ["deployment_moddel", "deployment_modl", "allow_network_copyleftt"])
def test_a_misspelled_policy_key_is_rejected_not_discarded(typo):
    with pytest.raises(ValidationError):
        LicensePolicySchema(**{typo: "cli_batch"})
    with pytest.raises(ValidationError):
        ProjectCreate(name="p", license_policy={typo: "cli_batch"})
    with pytest.raises(ValidationError):
        ProjectUpdate(license_policy={typo: "cli_batch"})


def test_the_persisted_and_the_one_shot_path_agree():
    """The ad-hoc request used to be the only one that refused unknown keys."""
    payload = {"deployment_moddel": "cli_batch", "allow_network_copyleft": True}

    with pytest.raises(ValidationError):
        ProjectCreate(name="p", license_policy=payload)
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[{"bomFormat": "CycloneDX"}], license_policy=payload)


def test_a_correct_policy_still_round_trips():
    policy = ProjectCreate(
        name="p", license_policy={"deployment_model": "cli_batch", "allow_network_copyleft": True}
    ).license_policy
    assert policy is not None
    assert policy.deployment_model == DeploymentModel.CLI_BATCH.value
    assert policy.allow_network_copyleft is True


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"license_compliance": {"deployment_model": "cli-batch"}}, id="flat-hyphen"),
        pytest.param({"license_compliance": {"license_policy": {"library_usage": "Unmodified"}}}, id="nested-case"),
        pytest.param({"license_compliance": {"distribution_model": "internal"}}, id="flat-truncated"),
    ],
)
def test_analyzer_settings_reject_values_the_analyzer_will_refuse(settings):
    """These wrote fine and then raised inside LicenseAnalyzer on every later scan of the project."""
    with pytest.raises(ValidationError):
        ProjectUpdate(analyzer_settings=settings)


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"license_compliance": {"ignore_dev_dependencies": True, "ignore_transitive": False}}, id="flags"),
        pytest.param({"license_compliance": {"deployment_model": "cli_batch"}}, id="valid-enum"),
        pytest.param({"trivy": {"anything": "goes"}}, id="other-analyzer-untouched"),
    ],
)
def test_analyzer_settings_stay_open_where_the_analyzer_is_open(settings):
    assert ProjectUpdate(analyzer_settings=settings).analyzer_settings == settings
