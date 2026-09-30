"""A request naming what the system never sends is refused rather than saved unread; stored documents read leniently."""

import pytest
from pydantic import ValidationError

from app.models.project import ProjectMember
from app.models.user import User
from app.schemas.project import ProjectNotificationSettings
from app.schemas.user import UserCreate, UserResponse, UserSignup, UserUpdate, UserUpdateMe

_UNKNOWN_EVENT = {"scan_kompletiert": ["email"], "vulnerability_found": ["email"]}
_UNKNOWN_CHANNEL = {"vulnerability_found": ["email", "teams"]}
_SANE = {"vulnerability_found": ["email"]}
_MUTED = {"analysis_completed": [], "vulnerability_found": []}

_REQUESTS = [
    pytest.param(lambda p: UserUpdate(notification_preferences=p), id="UserUpdate"),
    pytest.param(lambda p: UserUpdateMe(notification_preferences=p), id="UserUpdateMe"),
    pytest.param(
        lambda p: UserSignup(email="a@b.co", username="u", password="Str0ng!pass", notification_preferences=p),
        id="UserSignup",
    ),
    pytest.param(
        lambda p: UserCreate(email="a@b.co", username="u", password="Str0ng!pass", notification_preferences=p),
        id="UserCreate",
    ),
    pytest.param(lambda p: ProjectNotificationSettings(notification_preferences=p), id="ProjectNotificationSettings"),
]


@pytest.mark.parametrize("build", _REQUESTS)
@pytest.mark.parametrize("prefs", [_UNKNOWN_EVENT, _UNKNOWN_CHANNEL], ids=["unknown-event", "unknown-channel"])
def test_a_request_naming_what_the_system_never_sends_is_refused(build, prefs):
    with pytest.raises(ValidationError):
        build(prefs)


@pytest.mark.parametrize("build", _REQUESTS)
def test_a_request_muting_every_event_keeps_each_event(build):
    assert build(_MUTED).notification_preferences == _MUTED


@pytest.mark.parametrize("schema", [UserUpdate, UserUpdateMe])
def test_a_field_the_client_never_sent_stays_absent(schema):
    """`model_dump(exclude_unset=True)` drives these updates, so an unsent field must not arrive as
    an empty dict and wipe the stored preferences."""
    assert "notification_preferences" not in schema().model_dump(exclude_unset=True)


def test_every_reader_drops_what_a_stored_document_names_but_the_system_never_sends():
    on_read = User(username="u", email="a@b.co", notification_preferences=_UNKNOWN_EVENT).notification_preferences
    member = ProjectMember(user_id="u1", notification_preferences=_UNKNOWN_CHANNEL)
    response = UserResponse(_id="u1", email="a@b.co", username="u", notification_preferences=_UNKNOWN_EVENT)

    assert on_read == member.notification_preferences == response.notification_preferences == _SANE


def test_a_stored_mute_reads_back_as_a_mute():
    assert ProjectMember(user_id="u1", notification_preferences=_MUTED).notification_preferences == _MUTED
