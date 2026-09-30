"""Every deep link is joined onto FRONTEND_BASE_URL with a slash, so the setting never ends in one."""

from app.core.config import Settings


def test_a_trailing_slash_in_the_frontend_base_url_is_dropped():
    assert Settings(FRONTEND_BASE_URL="https://dc.example.com/").FRONTEND_BASE_URL == "https://dc.example.com"
