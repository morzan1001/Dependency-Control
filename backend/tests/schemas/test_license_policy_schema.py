"""LicensePolicySchema reuses the models/license.py enums and serializes to plain strings."""

import pytest
from pydantic import ValidationError

from app.models.license import DeploymentModel, DistributionModel, LibraryUsage
from app.schemas.project import LicensePolicySchema


def test_schema_fields_reuse_license_enums():
    fields = LicensePolicySchema.model_fields
    assert fields["distribution_model"].annotation is DistributionModel
    assert fields["deployment_model"].annotation is DeploymentModel
    assert fields["library_usage"].annotation is LibraryUsage


def test_accepted_values_match_enum_members():
    for value in DistributionModel:
        assert LicensePolicySchema(distribution_model=value.value)
    for value in DeploymentModel:
        assert LicensePolicySchema(deployment_model=value.value)
    for value in LibraryUsage:
        assert LicensePolicySchema(library_usage=value.value)


def test_invalid_value_rejected():
    with pytest.raises(ValidationError):
        LicensePolicySchema(distribution_model="not_a_real_model")


def test_serialization_contract_identical():
    policy = LicensePolicySchema(
        distribution_model="open_source",
        deployment_model="embedded",
        library_usage="modified",
    )
    dumped = policy.model_dump()
    assert dumped == {
        "distribution_model": "open_source",
        "deployment_model": "embedded",
        "library_usage": "modified",
        "allow_strong_copyleft": False,
        "allow_network_copyleft": False,
    }
    for key in ("distribution_model", "deployment_model", "library_usage"):
        assert type(dumped[key]) is str  # noqa: E721

    defaults = LicensePolicySchema().model_dump()
    assert defaults == {
        "distribution_model": "distributed",
        "deployment_model": "network_facing",
        "library_usage": "mixed",
        "allow_strong_copyleft": False,
        "allow_network_copyleft": False,
    }
    for key in ("distribution_model", "deployment_model", "library_usage"):
        assert type(defaults[key]) is str  # noqa: E721


def test_json_mode_serializes_to_strings():
    policy = LicensePolicySchema(distribution_model="internal_only")
    assert policy.model_dump(mode="json")["distribution_model"] == "internal_only"
