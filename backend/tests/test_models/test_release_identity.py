"""Both release writers name a release by one rule: the payload's version, else the scan's commit tag."""

import pytest

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from app.models.release import release_identity


@pytest.mark.parametrize(
    ("environment", "version", "commit_tag", "expected"),
    [
        (None, None, None, (DEFAULT_RELEASE_ENVIRONMENT, None)),
        ("", "", "v1", (DEFAULT_RELEASE_ENVIRONMENT, "v1")),
        ("staging", "v2", "v1", ("staging", "v2")),
    ],
)
def test_the_rule(environment, version, commit_tag, expected):
    assert release_identity(environment, version, commit_tag) == expected
