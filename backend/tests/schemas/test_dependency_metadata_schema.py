from app.schemas.analytics import DependencyMetadata


def test_each_affected_project_is_documented_with_its_fields():
    schema = DependencyMetadata.model_json_schema()

    ref = schema["properties"]["affected_projects"]["items"]["$ref"]
    project = schema["$defs"][ref.rsplit("/", 1)[1]]

    assert sorted(project["properties"]) == sorted(project["required"]) == ["direct", "id", "name"]
