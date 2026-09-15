"""The minimum length is the only password rule a short-but-otherwise-complex secret can violate,
so every field that accepts a password must reject it on length alone."""

import pytest
from pydantic import ValidationError

from app.schemas.user import (
    UserCreate,
    UserMigrateToLocal,
    UserPasswordReset,
    UserPasswordUpdate,
    UserSignup,
    validate_password_strength,
)

_TOO_SHORT = "Ab1!cde"
_SHORTEST_ALLOWED = "Ab1!cdef"
_LENGTH_ERROR = "at least 8 characters"


def test_a_seven_character_password_is_rejected_although_it_meets_every_other_rule():
    with pytest.raises(ValueError, match=_LENGTH_ERROR):
        validate_password_strength(_TOO_SHORT)


def test_eight_characters_is_the_shortest_accepted_password():
    assert validate_password_strength(_SHORTEST_ALLOWED) == _SHORTEST_ALLOWED


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda p: UserCreate(email="a@b.co", username="u", password=p), id="UserCreate"),
        pytest.param(lambda p: UserSignup(email="a@b.co", username="u", password=p), id="UserSignup"),
        pytest.param(
            lambda p: UserPasswordUpdate(current_password="whatever", new_password=p), id="UserPasswordUpdate"
        ),
        pytest.param(lambda p: UserMigrateToLocal(new_password=p), id="UserMigrateToLocal"),
        pytest.param(lambda p: UserPasswordReset(token="t", new_password=p), id="UserPasswordReset"),
    ],
)
def test_every_password_field_rejects_a_seven_character_password(build):
    with pytest.raises(ValidationError, match=_LENGTH_ERROR):
        build(_TOO_SHORT)

    assert build(_SHORTEST_ALLOWED) is not None
