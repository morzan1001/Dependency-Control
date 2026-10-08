"""A dependency search row carries the dependency's own fields under their own names."""

from app.api.v1.endpoints.analytics.search import _dep_to_search_result
from app.models.dependency import Dependency
from app.schemas.analytics import DependencySearchResult


def _populated() -> Dependency:
    return Dependency(
        id="dep-1",
        project_id="p1",
        scan_id="s1",
        name="jackson-core",
        version="2.17.0",
        purl="pkg:maven/com.fasterxml.jackson.core/jackson-core@2.17.0",
        type="maven",
        license="Apache-2.0",
        license_url="https://www.apache.org/licenses/LICENSE-2.0",
        direct=True,
        source_type="image",
        source_target="registry/app:1.0",
        layer_digest="sha256:abc",
        found_by="java-archive-cataloger",
        locations=["/app/lib/jackson-core.jar"],
        cpes=["cpe:2.3:a:fasterxml:jackson-core:2.17.0:*:*:*:*:*:*:*"],
        description="Core Jackson processing abstractions",
        author="FasterXML",
        publisher="FasterXML",
        group="com.fasterxml.jackson.core",
        homepage="https://github.com/FasterXML/jackson-core",
        repository_url="https://github.com/FasterXML/jackson-core.git",
        download_url="https://repo1.maven.org/jackson-core-2.17.0.jar",
        hashes={"sha256": "def"},
        properties={"syft:package:type": "java-archive"},
    )


def test_every_shared_field_is_the_dependencys_own():
    dep = _populated()

    result = _dep_to_search_result(dep, {"p1": "Project One"})

    assert (result.project_name, result.package) == ("Project One", "jackson-core")
    shared = DependencySearchResult.model_fields.keys() - {"project_name", "package"}
    assert {field: getattr(result, field) for field in shared} == {field: getattr(dep, field) for field in shared}


def test_an_unknown_project_reads_as_unknown():
    assert _dep_to_search_result(_populated(), {}).project_name == "Unknown"
