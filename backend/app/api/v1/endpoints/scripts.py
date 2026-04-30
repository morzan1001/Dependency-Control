"""
API endpoints for serving CI/CD scripts with integrity verification.

These scripts can be downloaded directly by pipelines for easy integration.
Script integrity is verified using SHA256 hashes.

## Versioning model

Released versions live under ``ci-cd/scripts/versions/scanner-X.Y.Z.sh``
and are **frozen** — once published they are never edited. The
top-level ``ci-cd/scripts/scanner.sh`` is the *latest pointer* and
matches whichever version is current.

Pipelines pin both ``SCANNER_VERSION`` and ``SCANNER_SHA256`` and pass
``?v=X.Y.Z`` when downloading; the endpoint then serves the matching
frozen file. Without ``?v=`` the latest pointer is returned (suitable
only for unpinned use). This means a deployment that ships a new
version never silently breaks pipelines pinned to an older one — they
keep downloading the exact bytes they reviewed.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Annotated, Optional

from fastapi import HTTPException, Query

from app.api.router import CustomAPIRouter
from fastapi.responses import PlainTextResponse

from app.schemas.scripts import ScriptInfo, ScriptManifest

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

SCRIPTS_DIR = Path("/app/ci-cd/scripts")
VERSIONS_DIR = SCRIPTS_DIR / "versions"

# Script configurations: name -> description
SCRIPT_CONFIG = {
    "scanner.sh": "Universal scanner script for all security scans",
}
ALLOWED_SCRIPTS = set(SCRIPT_CONFIG.keys())

# Restrict ?v= to a strict semver-shape so the value can be safely
# concatenated into a filename without allowing path traversal. The
# ASCII flag matters: bare \d matches Unicode digit categories (Arabic-
# Indic, Devanagari, ...) which would silently widen the input space.
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$", re.ASCII)


def validate_script_name(script_name: str) -> None:
    """
    Validate script name is allowed and safe from path traversal.

    Raises:
        HTTPException: 404 if script not allowed or path traversal detected
    """
    # Check whitelist first
    if script_name not in ALLOWED_SCRIPTS:
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found",
        )

    # Path traversal protection: ensure resolved path is within SCRIPTS_DIR
    script_path = (SCRIPTS_DIR / script_name).resolve()
    if not str(script_path).startswith(str(SCRIPTS_DIR.resolve())):
        logger.warning(f"Path traversal attempt detected for script: {script_name}")
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found",
        )


def get_script_version(content: str) -> str:
    """Extract version from script content."""
    match = re.search(r'SCRIPT_VERSION="([^"]+)"', content)
    if match:
        return match.group(1)
    return "unknown"


def compute_sha256(content: str) -> str:
    """Compute SHA256 hash of script content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _resolve_script_path(script_name: str, version: Optional[str]) -> Path:
    """Resolve the file path for ``script_name`` at the requested version.

    With no version, return the top-level latest pointer. With a
    version, return the matching frozen file under ``versions/`` after
    validating the version string against ``_VERSION_RE``.
    """
    if version is None:
        return (SCRIPTS_DIR / script_name).resolve()

    if not _VERSION_RE.fullmatch(version):
        raise HTTPException(
            status_code=400,
            detail="Invalid version. Expected semver-shape X.Y.Z (digits only).",
        )

    stem, dot, ext = script_name.partition(".")
    if not dot:
        raise HTTPException(status_code=400, detail="Invalid script name")
    versioned_name = f"{stem}-{version}.{ext}"
    return (VERSIONS_DIR / versioned_name).resolve()


def get_script_content(script_name: str, version: Optional[str] = None) -> tuple[str, str, str]:
    """
    Get script content, version, and hash for either the latest pointer
    (``version=None``) or a specific frozen release (``version="1.0.0"``).

    Args:
        script_name: Name of the script (must be validated first)
        version: Optional semver-shape version string

    Returns:
        Tuple of (content, version, sha256_hash)

    Raises:
        FileNotFoundError: If the resolved script file doesn't exist
    """
    script_path = _resolve_script_path(script_name, version)
    base = VERSIONS_DIR.resolve() if version else SCRIPTS_DIR.resolve()
    if not str(script_path).startswith(str(base)):
        raise FileNotFoundError(f"Script {script_name} not found")
    if not script_path.exists():
        raise FileNotFoundError(f"Script {script_name} not found")

    content = script_path.read_text()
    detected_version = get_script_version(content)
    sha256_hash = compute_sha256(content)

    return content, detected_version, sha256_hash


def list_available_versions(script_name: str) -> list[str]:
    """Return sorted list of versions present under ``versions/`` for
    ``script_name`` (e.g. ``["1.0.0", "1.1.0"]``).

    The directory is the source of truth; releases that haven't been
    frozen there aren't pinnable.
    """
    if not VERSIONS_DIR.is_dir():
        return []
    stem, dot, ext = script_name.partition(".")
    if not dot:
        return []
    pattern = re.compile(
        rf"^{re.escape(stem)}-(\d+\.\d+\.\d+)\.{re.escape(ext)}$",
        re.ASCII,
    )
    versions: list[str] = []
    for entry in VERSIONS_DIR.iterdir():
        match = pattern.match(entry.name)
        if match:
            versions.append(match.group(1))
    return sorted(versions, key=lambda v: tuple(int(p) for p in v.split(".")))


def build_script_info(script_name: str, version: Optional[str] = None) -> ScriptInfo:
    """
    Build ScriptInfo object for a script.

    Args:
        script_name: Name of the script (must be validated first)
        version: Optional pinned version; if omitted, the latest
            pointer is described.

    Returns:
        ScriptInfo object with script metadata

    Raises:
        FileNotFoundError: If script file doesn't exist
    """
    _, detected_version, sha256_hash = get_script_content(script_name, version)
    base_url = f"/api/v1/scripts/{script_name}"
    url = f"{base_url}?v={version}" if version else base_url
    return ScriptInfo(
        name=script_name,
        version=detected_version,
        sha256=sha256_hash,
        url=url,
        description=SCRIPT_CONFIG.get(script_name, "CI/CD script"),
    )


@router.get(
    "/scripts/{script_name}/hash",
    summary="Get Script Hash",
    responses={
        200: {"description": "Script hash and version information"},
        404: {"description": "Script not found"},
        500: {"description": "Internal server error"},
    },
)
async def get_script_hash(
    script_name: str,
    v: Annotated[
        Optional[str],
        Query(description="Pin a specific frozen release (e.g. '1.1.0'); omit for the latest pointer"),
    ] = None,
) -> ScriptInfo:
    """
    Get the SHA256 hash and version of a script for verification.

    Pass ``?v=X.Y.Z`` to ask for a specific frozen release (the bytes
    will not change once that version is published). Without ``?v`` the
    response describes whichever version is currently the latest
    pointer, which can change with every backend deploy — pipelines
    that pin a hash should always pin the version too.
    """
    validate_script_name(script_name)

    try:
        return build_script_info(script_name, version=v)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' (version={v or 'latest'}) not found on server",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting script hash for {script_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error reading script file",
        )


@router.get(
    "/scripts/{script_name}",
    summary="Get CI/CD Script",
    response_class=PlainTextResponse,
    responses={
        200: {
            "description": "Script content",
            "content": {"text/plain": {"example": "#!/bin/bash\n# Script content..."}},
        },
        400: {"description": "Invalid version format"},
        404: {"description": "Script not found"},
        500: {"description": "Internal server error"},
    },
)
async def get_script(
    script_name: str,
    v: Annotated[
        Optional[str],
        Query(description="Pin a specific frozen release (e.g. '1.1.0'); omit for the latest pointer"),
    ] = None,
) -> PlainTextResponse:
    """
    Download a CI/CD script for pipeline integration.

    Available scripts:
    - `scanner.sh` - Universal scanner script for all security scans

    **Versioning model**

    Each released version is frozen on disk under
    ``ci-cd/scripts/versions/scanner-X.Y.Z.sh`` and is never edited
    again. Pass ``?v=X.Y.Z`` to download an exact frozen release; omit
    it to receive the current latest pointer (whose bytes change
    whenever a new version is published).

    **Secure usage in pipelines (pinned)**

    ```bash
    # These values should be stored in your pipeline config
    SCANNER_VERSION="1.1.0"
    SCANNER_SHA256="<hash-from-manifest>"

    # Download the exact frozen release matching SCANNER_VERSION
    curl -sSfL "$DEP_CONTROL_URL/api/v1/scripts/scanner.sh?v=$SCANNER_VERSION" -o scanner.sh

    # Verify hash BEFORE execution (Linux)
    echo "$SCANNER_SHA256  scanner.sh" | sha256sum -c -

    # Or on macOS
    echo "$SCANNER_SHA256  scanner.sh" | shasum -a 256 -c -

    # Only run if verification passed
    chmod +x scanner.sh
    ./scanner.sh all
    ```

    Pinning ``?v`` means a future backend deploy that publishes a new
    version will not change the bytes you receive — your pipeline keeps
    running on the version you reviewed until you bump
    ``SCANNER_VERSION`` and ``SCANNER_SHA256`` together.

    **Available commands** (scanner.sh 1.1.0)

    - `sbom`       Generate and upload SBOM (Syft)
    - `cbom`       Upload a pre-built CycloneDX 1.6 CBOM
    - `secrets`    Run TruffleHog secret scan
    - `sast`       Run OpenGrep/Semgrep SAST scan
    - `iac`        Run KICS IaC scan
    - `bearer`     Run Bearer privacy/security scan
    - `callgraph`  Generate and upload callgraph for reachability analysis
    - `all`        Run all enabled scans
    """
    validate_script_name(script_name)

    try:
        content, version, sha256_hash = get_script_content(script_name, version=v)

        return PlainTextResponse(
            content=content,
            media_type="text/plain",
            headers={
                "Content-Disposition": f"inline; filename={script_name}",
                "X-Script-Version": version,
                "X-Script-SHA256": sha256_hash,
                "Cache-Control": "no-cache",
            },
        )
    except FileNotFoundError:
        logger.error(f"Script file not found: {script_name} (version={v or 'latest'})")
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' (version={v or 'latest'}) not found on server",
        )
    except HTTPException:
        # _resolve_script_path may raise 400 for an invalid version shape;
        # propagate without converting to 500.
        raise
    except Exception as e:
        logger.error(f"Error reading script {script_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error reading script file",
        )


@router.get(
    "/scripts",
    summary="List Available Scripts with Hashes",
)
async def list_scripts() -> ScriptManifest:
    """
    List all available CI/CD scripts with their SHA256 hashes.

    Each script entry includes the **latest pointer** plus every frozen
    release found under ``ci-cd/scripts/versions/``. Pin the
    ``version`` and ``sha256`` of a specific release in your pipeline
    so future deploys can never silently change the bytes you run.

    **Workflow for setting up a new project**

    1. Call this endpoint to enumerate available versions.
    2. Pick a frozen release (highest version unless you have a reason).
    3. Pin its ``version`` and ``sha256`` in your pipeline configuration.
    4. Download with ``?v=<version>`` so the bytes are immutable.

    **Workflow for upgrading**

    1. Re-check this manifest for new frozen versions.
    2. Review the changelog and the new SHA256.
    3. Bump both ``version`` and ``sha256`` in your pipeline together.
    4. Commit the change.
    """
    scripts: list[ScriptInfo] = []
    errors = []

    for script_name in ALLOWED_SCRIPTS:
        try:
            scripts.append(build_script_info(script_name))
        except Exception as e:
            logger.error(f"Error getting {script_name} info: {e}")
            errors.append(script_name)

        for version in list_available_versions(script_name):
            try:
                scripts.append(build_script_info(script_name, version=version))
            except Exception as e:
                logger.error(f"Error getting {script_name} v{version} info: {e}")
                errors.append(f"{script_name}@{version}")

    # Log warning if some scripts couldn't be loaded
    if errors:
        logger.warning(f"Failed to load scripts: {', '.join(errors)}")

    return ScriptManifest(
        scripts=scripts,
        verification_command_linux='echo "$SCANNER_SHA256  scanner.sh" | sha256sum -c -',
        verification_command_macos='echo "$SCANNER_SHA256  scanner.sh" | shasum -a 256 -c -',
    )
