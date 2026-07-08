"""Serve CI/CD scripts with SHA256 integrity verification; ?v=X.Y.Z serves a frozen versioned file, no ?v serves the mutable latest pointer."""

import hashlib
import logging
import re
from functools import lru_cache
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

SCRIPT_CONFIG = {
    "scanner.sh": "Universal scanner script for all security scans",
}
ALLOWED_SCRIPTS = set(SCRIPT_CONFIG.keys())

# Strict semver shape so ?v= is safe to concatenate into a filename. The ASCII
# flag matters: bare \d matches Unicode digit categories, widening the input.
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$", re.ASCII)


def validate_script_name(script_name: str) -> None:
    """Validate script name is allowed and safe from path traversal (404 otherwise)."""
    if script_name not in ALLOWED_SCRIPTS:
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found",
        )

    # is_relative_to (not str.startswith) so a sibling like scripts/foo-evil is rejected.
    script_path = (SCRIPTS_DIR / script_name).resolve()
    if not script_path.is_relative_to(SCRIPTS_DIR.resolve()):
        logger.warning(f"Path traversal attempt detected for script: {script_name}")
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found",
        )


def get_script_version(content: str) -> str:
    match = re.search(r'SCRIPT_VERSION="([^"]+)"', content)
    if match:
        return match.group(1)
    return "unknown"


def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _resolve_script_path(script_name: str, version: Optional[str]) -> Path:
    """Resolve the file path for script_name: the latest pointer if no version, else the validated frozen file under versions/."""
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


def _read_and_describe(script_path: Path) -> tuple[str, str, str]:
    """Read a script file and compute (content, embedded_version, sha256)."""
    content = script_path.read_text()
    return content, get_script_version(content), compute_sha256(content)


@lru_cache(maxsize=256)
def _read_and_describe_frozen(script_path_str: str) -> tuple[str, str, str]:
    """Cached read+hash for frozen versions, whose bytes never change; the latest pointer is not cached."""
    return _read_and_describe(Path(script_path_str))


def get_script_content(script_name: str, version: Optional[str] = None) -> tuple[str, str, str]:
    """Return (content, version, sha256) for the latest pointer (version=None) or a specific frozen release."""
    script_path = _resolve_script_path(script_name, version)
    base = VERSIONS_DIR.resolve() if version else SCRIPTS_DIR.resolve()
    # is_relative_to avoids the str.startswith prefix-collision (e.g. versions-evil vs versions).
    if not script_path.is_relative_to(base):
        raise FileNotFoundError(f"Script {script_name} not found")
    if not script_path.exists():
        raise FileNotFoundError(f"Script {script_name} not found")

    if version is not None:
        return _read_and_describe_frozen(str(script_path))
    return _read_and_describe(script_path)


def list_available_versions(script_name: str) -> list[str]:
    """Return the sorted versions present under versions/ for script_name."""
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
    """Build a ScriptInfo for a script at the given version (or the latest pointer)."""
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
        400: {"description": "Invalid version format"},
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
    """Get the SHA256 hash and version of a script for verification; pass ?v=X.Y.Z for a frozen release."""
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
        logger.exception("Error getting script hash for %s: %s", script_name, e)
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
    """Download a CI/CD script for pipeline integration; pass ?v=X.Y.Z for a frozen release, omit for the latest pointer."""
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
        logger.exception("Script file not found: %s (version=%s)", script_name, v or "latest")
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' (version={v or 'latest'}) not found on server",
        )
    except HTTPException:
        # Propagate _resolve_script_path's 400 without converting to 500.
        raise
    except Exception as e:
        logger.exception("Error reading script %s: %s", script_name, e)
        raise HTTPException(
            status_code=500,
            detail="Error reading script file",
        )


@router.get(
    "/scripts",
    summary="List Available Scripts with Hashes",
)
async def list_scripts() -> ScriptManifest:
    """List available CI/CD scripts with their SHA256 hashes: the latest pointer plus every frozen release."""
    scripts: list[ScriptInfo] = []
    errors = []

    for script_name in ALLOWED_SCRIPTS:
        try:
            scripts.append(build_script_info(script_name))
        except Exception as e:
            logger.exception("Error getting %s info: %s", script_name, e)
            errors.append(script_name)

        for version in list_available_versions(script_name):
            try:
                scripts.append(build_script_info(script_name, version=version))
            except Exception as e:
                logger.exception("Error getting %s v%s info: %s", script_name, version, e)
                errors.append(f"{script_name}@{version}")

    if errors:
        logger.warning(f"Failed to load scripts: {', '.join(errors)}")

    return ScriptManifest(
        scripts=scripts,
        verification_command_linux='echo "$SCANNER_SHA256  scanner.sh" | sha256sum -c -',
        verification_command_macos='echo "$SCANNER_SHA256  scanner.sh" | shasum -a 256 -c -',
    )
