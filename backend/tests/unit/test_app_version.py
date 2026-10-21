from app.core import metrics
from app.main import app


def test_the_openapi_document_carries_the_installed_package_version():
    assert app.openapi()["info"]["version"] == metrics.APP_VERSION
