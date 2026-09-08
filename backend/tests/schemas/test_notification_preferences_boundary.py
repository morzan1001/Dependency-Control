"""A preference the system will never honour must not be accepted, echoed back and stored.

The sanitizer was wired into the storage models only, so an unknown event survived the request
schema, the response and the database, and was dropped where nobody could see it — the UI showed
the preference saved while the notification service never read it.
"""

import pytest

from app.models.project import ProjectMember
from app.models.user import User
from app.schemas.project import ProjectMemberUpdate, ProjectNotificationSettings
from app.schemas.user import UserSignup, UserUpdate, UserUpdateMe

_TYPO = {"scan_kompletiert": ["email"], "vulnerability_found": ["email"]}
_SANE = {"vulnerability_found": ["email"]}


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda p: UserUpdate(notification_preferences=p), id="UserUpdate"),
        pytest.param(lambda p: UserUpdateMe(notification_preferences=p), id="UserUpdateMe"),
        pytest.param(
            lambda p: UserSignup(email="a@b.co", username="u", password="Str0ng!pass", notification_preferences=p),
            id="UserSignup",
        ),
        pytest.param(lambda p: ProjectMemberUpdate(notification_preferences=p), id="ProjectMemberUpdate"),
        pytest.param(lambda p: ProjectNotificationSettings(notification_preferences=p), id="ProjectNotificationSettings"),
    ],
)
def test_request_schemas_drop_what_the_reader_would_drop(build):
    assert build(_TYPO).notification_preferences == _SANE


@pytest.mark.parametrize("schema", [UserUpdate, UserUpdateMe, ProjectMemberUpdate])
def test_a_field_the_client_never_sent_stays_absent(schema):
    """`model_dump(exclude_unset=True)` drives these updates, so an unsent field must not arrive as
    an empty dict and wipe the stored preferences."""
    assert "notification_preferences" not in schema().model_dump(exclude_unset=True)


def test_the_boundary_and_the_reader_now_agree():
    """The request schema and the model that reads the value back must reach the same answer."""
    at_the_boundary = UserUpdateMe(notification_preferences=_TYPO).notification_preferences
    on_read = User(
        username="u", email="a@b.co", hashed_password="x", notification_preferences=_TYPO
    ).notification_preferences
    member = ProjectMember(user_id="u1", role="viewer", notification_preferences=_TYPO)

    assert at_the_boundary == on_read == member.notification_preferences == _SANE
