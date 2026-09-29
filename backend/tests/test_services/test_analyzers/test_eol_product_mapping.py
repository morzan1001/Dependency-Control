"""NAME_TO_EOL_MAPPING names real endoflife.date products, and a component's CPE and name both count."""

import json
from pathlib import Path

import pytest

from app.core.constants import NAME_TO_EOL_MAPPING
from app.services.analyzers.end_of_life import collect_products_to_check

# /api/all.json of endoflife.date, fetched 2026-09-29; refresh it when a product is renamed upstream.
_PRODUCTS = set(json.loads((Path(__file__).parents[2] / "fixtures" / "endoflife_products.json").read_text()))


def test_every_mapping_target_is_an_endoflife_product():
    assert sorted({target for target in NAME_TO_EOL_MAPPING.values() if target not in _PRODUCTS}) == []


@pytest.mark.parametrize(
    ("name", "cpes", "expected"),
    [
        ("spring-boot", ["cpe:2.3:a:vmware:spring_boot:2.7.0:*:*:*:*:*:*:*"], {"spring-boot"}),
        ("spring-core", ["cpe:2.3:a:vmware:spring_framework:5.3.0:*:*:*:*:*:*:*"], {"spring-framework"}),
        ("httpd", ["cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*"], {"apache-http-server"}),
        ("rails", ["cpe:2.3:a:rubyonrails:ruby_on_rails:6.0.0:*:*:*:*:*:*:*"], {"rails"}),
        ("alpine-baselayout", [], {"alpine-baselayout"}),
        ("alpine", [], {"alpine-linux"}),
        ("tomcat", [], {"tomcat"}),
        ("log4j-core", ["cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"], {"log4j"}),
        ("@angular/core", ["cpe:2.3:a:angular:angular:12.0.0:*:*:*:*:*:*:*"], {"angularjs", "angular"}),
    ],
)
def test_the_products_checked_for_a_component(name, cpes, expected):
    assert set(collect_products_to_check([{"name": name, "version": "1.0", "cpes": cpes}])) == expected
