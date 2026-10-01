"""The backend image runs one uvicorn process per pod; WORKER_COUNT sizes the analysis workers only."""

import os
import subprocess
from pathlib import Path

import pytest

_ENTRYPOINT = Path(__file__).parents[2] / "docker-entrypoint.sh"


def _uvicorn_argv(tmp_path: Path, **env: str) -> list[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    uvicorn = stubs / "uvicorn"
    uvicorn.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n')
    uvicorn.chmod(0o755)
    capture = tmp_path / "argv"
    base = {
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "TMPDIR": str(tmp_path),
        "TRIVY_SERVER_URL": "http://trivy.invalid",
        "GRYPE_DB_SHARED": "true",
        "WORKER_COUNT": "2",
        "CAPTURE": str(capture),
    }
    subprocess.run(["sh", str(_ENTRYPOINT)], env=base | env, check=True, timeout=30, capture_output=True)
    return capture.read_text().splitlines()


@pytest.mark.parametrize("tls", [False, True])
def test_the_entrypoint_starts_one_uvicorn_process_whatever_the_worker_count(tls, tmp_path):
    env = {}
    if tls:
        for name in ("cert", "key"):
            (tmp_path / name).write_text("")
        env = {"TLS_ENABLED": "true", "TLS_CERT_PATH": str(tmp_path / "cert"), "TLS_KEY_PATH": str(tmp_path / "key")}

    argv = _uvicorn_argv(tmp_path, **env)

    assert argv[0] == "app.main:app"
    assert "--workers" not in argv
