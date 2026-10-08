"""The live scanner uploads the same sbom and cbom bodies as the frozen 1.2.0 release, a release mark only for an
environment the ingest accepts, and each callgraph to the project the ingest config names."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_api.test_callgraph_parsers import MADGE_OUTPUT

_REPO = Path(__file__).parents[3]
_SCRIPTS = _REPO / "ci-cd" / "scripts"
_FIXTURES = Path(__file__).parents[1] / "fixtures"

# Answers with the API's real shapes: /ingest/config names the project, and no route lists projects to a CI token.
_CURL_STUB = """#!/usr/bin/env bash
url="${!#}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) cp "${2#@}" "$CAPTURE"; echo "$url" >> "$CAPTURE.urls"; shift ;;
        -T) cp "$2" "$CAPTURE"; echo "$url" >> "$CAPTURE.urls"; shift ;;
    esac
    shift
done
case "$url" in
    */ingest/config) printf '{"active_analyzers": ["reachability"], "project_id": "p1"}\\n200' ;;
    */api/v1/projects/*) printf '{"status": "queued"}\\n202' ;;
    */api/v1/ingest*) printf '{"status": "queued"}\\n202' ;;
    *) printf '{"detail": "Not Found"}\\n404' ;;
esac
"""

_GO_STUB = r"""#!/usr/bin/env python3
import json, os, sys

args = sys.argv[1:]
if args[:2] == ["list", "-deps"]:
    sys.stdout.write(os.environ["STUB_GO_PACKAGES"])
elif args == ["list", "-m", "-f", "{{if not (or .Main .Indirect)}}{{.Path}}{{end}}", "all"]:
    for module in json.loads(os.environ["STUB_GO_MODULES"]):
        print("" if module.get("Main") or module.get("Indirect") else module["Path"])
else:
    sys.exit(f"unexpected go invocation: {args}")
"""
_GO_PACKAGES = "\n".join(
    json.dumps(package)
    for package in (
        {
            "Dir": ".",
            "ImportPath": "example.com/app",
            "Module": {"Path": "example.com/app", "Main": True},
            "Imports": ["fmt", "github.com/sirupsen/logrus"],
        },
        {"ImportPath": "fmt", "Standard": True},
        {"ImportPath": "github.com/sirupsen/logrus", "Module": {"Path": "github.com/sirupsen/logrus"}},
    )
)
_GO_MODULES = json.dumps(
    [
        {"Path": "example.com/app", "Main": True},
        {"Path": "github.com/sirupsen/logrus"},
        {"Path": "golang.org/x/sys", "Indirect": True},
    ]
)


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(body)
    path.chmod(0o755)


def _run(script: Path, command: str, tmp_path: Path, files: dict[str, str], **extra_env: str) -> Path:
    """Run the scanner in a checkout holding ``files``; returns where the curl stub captured the upload."""
    stubs, workdir = tmp_path / "bin", tmp_path / "repo"
    stubs.mkdir(parents=True)
    workdir.mkdir()
    for name, content in files.items():
        (workdir / name).parent.mkdir(parents=True, exist_ok=True)
        (workdir / name).write_text(content)
    (tmp_path / "madge.json").write_text(MADGE_OUTPUT)
    _stub(stubs, "curl", _CURL_STUB)
    _stub(stubs, "syft", f"#!/bin/sh\ncat '{_FIXTURES / 'sbom' / 'mono.syft.json'}'\n")
    _stub(stubs, "madge", f"#!/bin/sh\ncat '{tmp_path / 'madge.json'}'\n")
    _stub(stubs, "go", _GO_STUB)
    capture = tmp_path / "body.json"
    env = {
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "DEP_CONTROL_URL": "http://dc.invalid",
        "DEP_CONTROL_API_KEY": "dck_test",
        "PROJECT_NAME": "group/mono",
        "BRANCH": "main",
        "COMMIT_HASH": "a" * 40,
        "PIPELINE_ID": "4711",
        "PIPELINE_IID": "12",
        "JOB_ID": "99",
        "JOB_STARTED_AT": "2026-09-30T08:00:00Z",
        "COMMIT_MESSAGE": 'fix: quote "this" and\nthat',
        "CBOM_FILE": str(_FIXTURES / "cbom" / "legacy_crypto_mixed.json"),
        "CAPTURE": str(capture),
        "STUB_GO_PACKAGES": _GO_PACKAGES,
        "STUB_GO_MODULES": _GO_MODULES,
        **extra_env,
    }
    subprocess.run(["bash", str(script), command], cwd=workdir, env=env, check=True, timeout=60, capture_output=True)
    return capture


def _uploaded_body(script: Path, command: str, tmp_path: Path, **extra_env: str) -> Any:
    return json.loads(_run(script, command, tmp_path, {"package.json": "{}"}, **extra_env).read_text())


@pytest.mark.parametrize("command", ["sbom", "cbom"])
def test_the_uploaded_body_matches_the_frozen_1_2_0_release(command, tmp_path):
    assert shutil.which("bash") and shutil.which("jq"), "the scanner needs bash and jq"

    frozen = _uploaded_body(_SCRIPTS / "versions" / "scanner-1.2.0.sh", command, tmp_path / "frozen")
    live = _uploaded_body(_SCRIPTS / "scanner.sh", command, tmp_path / "live")

    assert live == frozen


def test_an_environment_the_ingest_would_reject_drops_the_whole_release_mark(tmp_path):
    """Dropping only the environment would still mark the scan, and the ingest would file it under production."""
    body = _uploaded_body(
        _SCRIPTS / "scanner.sh",
        "sbom",
        tmp_path,
        DEP_CONTROL_IS_RELEASE="true",
        DEP_CONTROL_RELEASE_ENVIRONMENT="staging eu",
    )

    assert (body["is_release"], body["release_environment"]) == (False, None)


_CALLGRAPH_META = {"pipeline_id": 4711, "branch": "main", "commit_hash": "a" * 40}


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        pytest.param(
            {"package.json": "{}"},
            {"format": "madge", "language": "javascript", "data": json.loads(MADGE_OUTPUT)},
            id="javascript",
        ),
        pytest.param(
            {"pyproject.toml": "[project]\nname = 'demo'\n", "app/client.py": "import requests\nfrom . import x\n"},
            {
                "format": "generic",
                "language": "python",
                "data": {
                    "imports": [{"module": "requests", "file": "app/client.py", "line": 1, "symbols": []}],
                    "analyzed_modules": [],
                },
            },
            id="python",
        ),
        pytest.param(
            {"go.mod": "module example.com/app\n"},
            {
                "format": "generic",
                "language": "go",
                "data": {
                    "imports": [{"module": "github.com/sirupsen/logrus", "file": ".", "line": 0, "symbols": []}],
                    "analyzed_modules": ["github.com/sirupsen/logrus"],
                },
            },
            id="go",
        ),
    ],
)
def test_a_callgraph_goes_to_the_project_the_ingest_config_names(files, expected, tmp_path):
    capture = _run(_SCRIPTS / "scanner.sh", "callgraph", tmp_path, files)

    assert capture.with_name("body.json.urls").read_text().split() == ["http://dc.invalid/api/v1/projects/p1/callgraph"]
    assert json.loads(capture.read_text()) == {**expected, **_CALLGRAPH_META}
