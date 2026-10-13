"""A profile email change answers over HTTP whether it waits for the mailed link or applied at once."""

from unittest.mock import AsyncMock, patch

import pytest

from tests.helpers.auth import bearer_headers

_LENA = {
    "_id": "lena",
    "username": "lena",
    "email": "lena@test.com",
    "auth_provider": "local",
    "is_verified": True,
    "permissions": [],
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("smtp_host", "answer", "mailed_to"),
    [
        ("smtp.test", ("lena@test.com", "lena.new@corp.com", True, "pending_confirmation"), ["lena.new@corp.com"]),
        (None, ("lena.new@corp.com", None, False, "changed"), []),
    ],
    ids=["mail-server", "no-mail-server"],
)
async def test_the_answer_names_the_outcome_with_the_account(client, db, smtp_host, answer, mailed_to):
    await db.users.insert_one(dict(_LENA))
    await db.system_settings.insert_one({"_id": "current", "smtp_host": smtp_host})

    with patch("app.api.v1.helpers.auth.EmailProvider.send", new_callable=AsyncMock) as send:
        resp = await client.post(
            "/api/v1/users/me/email", json={"email": "Lena.New@Corp.com"}, headers=bearer_headers("lena", [])
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["email"], body["pending_email"], body["is_verified"], body["email_change"]) == answer
    assert [call.kwargs["destination"] for call in send.await_args_list] == mailed_to
