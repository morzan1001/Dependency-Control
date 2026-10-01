"""The live scanner uploads the same sbom, cbom and callgraph bodies as the frozen 1.2.0 release."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_api.test_callgraph_parsers import MADGE_OUTPUT

_REPO = Path(__file__).parents[3]
_SCRIPTS = _REPO / "ci-cd" / "scripts"
_FIXTURES = Path(__file__).parents[1] / "fixtures"

_CURL_STUB = """#!/usr/bin/env bash
url="${!#}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) cp "${2#@}" "$CAPTURE"; shift ;;
        -T) cp "$2" "$CAPTURE"; shift ;;
    esac
    shift
done
case "$url" in
    */ingest/config) printf '{"active_analyzers": ["reachability"]}\\n200' ;;
    *"/projects?name="*) printf '[{"_id": "p1"}]' ;;
    *) printf '{"status": "queued"}\\n202' ;;
esac
"""


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(body)
    path.chmod(0o755)


def _uploaded_body(script: Path, command: str, tmp_path: Path) -> object:
    stubs, workdir = tmp_path / "bin", tmp_path / "repo"
    stubs.mkdir(parents=True)
    workdir.mkdir()
    (workdir / "package.json").write_text("{}")
    (tmp_path / "madge.json").write_text(MADGE_OUTPUT)
    _stub(stubs, "curl", _CURL_STUB)
    _stub(stubs, "syft", f"#!/bin/sh\ncat '{_FIXTURES / 'sbom' / 'mono.syft.json'}'\n")
    _stub(stubs, "madge", f"#!/bin/sh\ncat '{tmp_path / 'madge.json'}'\n")
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
    }
    subprocess.run(["bash", str(script), command], cwd=workdir, env=env, check=True, timeout=60, capture_output=True)
    return json.loads(capture.read_text())


@pytest.mark.parametrize("command", ["sbom", "cbom", "callgraph"])
def test_the_uploaded_body_matches_the_frozen_1_2_0_release(command, tmp_path):
    assert shutil.which("bash") and shutil.which("jq"), "the scanner needs bash and jq"

    frozen = _uploaded_body(_SCRIPTS / "versions" / "scanner-1.2.0.sh", command, tmp_path / "frozen")
    live = _uploaded_body(_SCRIPTS / "scanner.sh", command, tmp_path / "live")

    assert live == frozen
