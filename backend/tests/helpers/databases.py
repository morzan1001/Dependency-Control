import pytest

# The value is unread: the marker on the second case makes the ``db`` fixture hand out a real server.
DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]
