"""A license policy that is not what the caller wrote is worse than a rejected one: it is stored on
the project and re-applied to every future scan, and the only symptom is a severity that moved."""

import pytest
from pydantic import ValidationError

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.schemas.project import LicensePolicySchema, ProjectCreate, ProjectUpdate


def _license_settings(entry):
    return {"license_compliance": entry}


@pytest.mark.parametrize("typo", ["deployment_moddel", "deployment", "allow_network_copyleftt"])
def test_a_misspelled_policy_key_is_rejected_not_discarded(typo):
    with pytest.raises(ValidationError):
        LicensePolicySchema(**{typo: "cli_batch"})
    with pytest.raises(ValidationError):
        ProjectUpdate(analyzer_settings=_license_settings({typo: "cli_batch"}))


def test_the_persisted_and_the_one_shot_path_agree():
    payload = {"deployment_moddel": "cli_batch", "allow_network_copyleft": True}

    with pytest.raises(ValidationError):
        ProjectUpdate(analyzer_settings=_license_settings(payload))
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[{"bomFormat": "CycloneDX"}], license_policy=payload)


def test_a_nested_license_policy_is_rejected():
    """The scan reads the flat keys only, so a nested policy would be stored and never applied."""
    with pytest.raises(ValidationError):
        ProjectUpdate(analyzer_settings=_license_settings({"license_policy": {"distribution_model": "internal_only"}}))


@pytest.mark.parametrize("model", [ProjectCreate, ProjectUpdate])
def test_a_string_boolean_is_stored_as_the_bool_the_scan_reads(model):
    """A string 'false' is stored as False, so the scan does not read it as allowed."""
    fields = {"name": "p"} if model is ProjectCreate else {}
    settings = model(
        **fields, analyzer_settings=_license_settings({"allow_strong_copyleft": "false", "ignore_transitive": "true"})
    ).analyzer_settings

    assert settings == _license_settings({"allow_strong_copyleft": False, "ignore_transitive": True})


def test_only_the_keys_the_caller_sent_are_stored():
    settings = ProjectUpdate(
        analyzer_settings=_license_settings({"deployment_model": "cli_batch", "allow_network_copyleft": True})
    ).analyzer_settings

    assert settings == _license_settings({"deployment_model": "cli_batch", "allow_network_copyleft": True})


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"license_compliance": {"deployment_model": "cli-batch"}}, id="flat-hyphen"),
        pytest.param({"license_compliance": {"library_usage": "Unmodified"}}, id="flat-case"),
        pytest.param({"license_compliance": {"distribution_model": "internal"}}, id="flat-truncated"),
        pytest.param({"license_compliance": {"allow_strong_copyleft": "maybe"}}, id="not-a-bool"),
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
