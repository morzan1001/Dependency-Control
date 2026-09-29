"""An advisory's inclusive max version, compared across the version schemes SBOMs carry."""

import pytest
from pydantic import ValidationError

from app.schemas.notification import AdvisoryPackage


@pytest.mark.parametrize(
    ("installed", "bound", "affected"),
    [
        ("4.1.100.Final", "4.1.100", True),
        ("5.2.9.RELEASE", "5.2.9", True),
        ("4.1.100.Final", "2.17.0", False),
        ("2.20.0-SNAPSHOT", "2.17.0", False),
        ("2.17.0-SNAPSHOT", "2.17.0", True),
        ("2.17.0-M1", "2.17.0", True),
        ("4.1.101.Final", "4.1.100.Final", False),
        ("2.0.0-beta.1", "2.0.0", True),
        ("v0.0.0-20210101000000-abcdef123456", "0.1.0", True),
        ("1:2.30-1", "2.29", False),
        ("2.15.0", "2.14.1", False),
        ("1.1.1a", "1.1.1", False),
        ("1.1.1", "1.1.1a", True),
        ("2.14.0", "2.14", True),
        ("2.0.0", "2", True),
        ("latest", "1.0.0", None),
    ],
)
def test_a_version_is_covered_up_to_the_bound_it_names(installed, bound, affected):
    """None: the installed version names no release the bound could be compared with."""
    assert AdvisoryPackage(name="pkg", version=bound).covers(installed) is affected


def test_a_rule_without_a_bound_covers_every_version():
    assert AdvisoryPackage(name="pkg", version="").covers("99.0") is True


@pytest.mark.parametrize("bound", ["2.14.x", "2.*", "<=2.14", "latest"])
def test_a_bound_that_names_no_version_is_rejected(bound):
    with pytest.raises(ValidationError):
        AdvisoryPackage(name="pkg", version=bound)


@pytest.mark.parametrize(("given", "stored"), [("pip", "pypi"), ("Go", "golang"), ("", None), ("maven", "maven")])
def test_the_ecosystem_is_named_by_its_purl_type(given, stored):
    assert AdvisoryPackage(name="pkg", type=given).type == stored


@pytest.mark.parametrize("given", ["bogus", "java-archive", "Python Package"])
def test_a_type_that_is_no_purl_type_is_rejected(given):
    with pytest.raises(ValidationError):
        AdvisoryPackage(name="pkg", type=given)


@pytest.mark.parametrize("given", ["cargo", "deb", "gem", "conan"])
def test_any_purl_type_is_accepted(given):
    assert AdvisoryPackage(name="pkg", type=given).type == given
