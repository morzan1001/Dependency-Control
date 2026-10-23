import base64
import threading
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
import qrcode

from app.api.v1.endpoints import users
from app.core.config import settings
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase


async def _setup(db: FakeDatabase | None = None) -> dict[str, str]:
    db = db or FakeDatabase()
    user = User(id="u-1", username="alice", email="alice@corp.example")
    await db.users.insert_one(user.model_dump(by_alias=True))
    return await users.setup_2fa(user, db)


@pytest.mark.asyncio
async def test_the_qr_code_is_rendered_off_the_event_loop():
    """Rendering and PNG-encoding take long enough to stall every other request on the loop."""
    loop_thread = threading.get_ident()
    rendered_on = []
    real_make = qrcode.make

    def make(data):
        rendered_on.append(threading.get_ident())
        return real_make(data)

    with patch.object(qrcode, "make", side_effect=make):
        result = await _setup()

    assert rendered_on
    assert loop_thread not in rendered_on
    assert base64.b64decode(result["qr_code"]).startswith(b"\x89PNG")


async def _issued_uri(db: FakeDatabase) -> str:
    encoded = []
    real_make = qrcode.make

    def make(data):
        encoded.append(data)
        return real_make(data)

    with patch.object(qrcode, "make", side_effect=make):
        await _setup(db)

    [uri] = encoded
    return uri


@pytest.mark.asyncio
async def test_the_authenticator_entry_is_issued_by_the_instance_name():
    db = FakeDatabase()
    await db.system_settings.insert_one({"_id": "current", "instance_name": "Acme Deps"})

    uri = await _issued_uri(db)

    assert parse_qs(urlparse(uri).query)["issuer"] == ["Acme Deps"]
    assert urlparse(uri).path == "/Acme%20Deps:alice%40corp.example"


@pytest.mark.asyncio
async def test_the_authenticator_entry_is_issued_by_the_deployment_name_while_the_instance_name_keeps_its_default(
    monkeypatch,
):
    monkeypatch.setattr(settings, "PROJECT_NAME", "ACME Security")

    uri = await _issued_uri(FakeDatabase())

    assert parse_qs(urlparse(uri).query)["issuer"] == ["ACME Security"]
