"""
API endpoints for serving CI/CD scripts with integrity verification.

These scripts can be downloaded directly by pipelines for easy integration.
Script integrity is verified using SHA256 hashes.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app.schemas.scripts import ScriptInfo, ScriptManifest

logger = logging.getLogger(__name__)

router = APIRouter()

SCRIPTS_DIR = Path("/app/ci-cd/scripts")
ALLOWED_SCRIPTS = {"scanner.sh"}

def get_script_version(content: str) -> str:
    """Extract version from script content."""
    match = re.search(r'SCRIPT_VERSION="([^"]+)"', content)
    if match:
        return match.group(1)
    return "unknown"


def compute_sha256(content: str) -> str:
    """Compute SHA256 hash of script content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_script_content(script_name: str) -> tuple[str, str, str]:
    """
    Get script content, version, and hash.

    Returns:
        Tuple of (content, version, sha256_hash)
    """
    script_path = SCRIPTS_DIR / script_name

    if not script_path.exists():
        raise FileNotFoundError(f"Script {script_name} not found")

    content = script_path.read_text()
    version = get_script_version(content)
    sha256_hash = compute_sha256(content)

    return content, version, sha256_hash


@router.get(
    "/scripts/{script_name}/hash",
    summary="Get Script Hash",
    response_model=ScriptInfo,
    responses={
        200: {"description": "Script hash and version information"},
        404: {"description": "Script not found"},
    },
)
async def get_script_hash(script_name: str) -> ScriptInfo:
    """
    Get the SHA256 hash and version of a script for verification.

    Use this endpoint to get the current hash of a script. Store this hash
    in your pipeline configuration to verify script integrity before execution.

    **Important:** The hash should be stored in your repository, not fetched
    dynamically. This ensures you control when script updates are applied.
    """
    if script_name not in ALLOWED_SCRIPTS:
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found.",
        )

    try:
        _, version, sha256_hash = get_script_content(script_name)

        return ScriptInfo(
            name=script_name,
            version=version,
            sha256=sha256_hash,
            url=f"/api/v1/scripts/{script_name}",
            description="Universal scanner script for all security scans",
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found on server.",
        )
    except Exception as e:
        logger.error(f"Error getting script hash for {script_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error reading script file.",
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
        404: {"description": "Script not found"},
    },
)
async def get_script(
    script_name: str,
    v: Optional[str] = Query(None, description="Expected version (for logging)"),
) -> PlainTextResponse:
    """
    Download a CI/CD script for pipeline integration.

    Available scripts:
    - `scanner.sh` - Universal scanner script for all security scans

    **Secure usage in pipelines:**

    ```bash
    # These values should be stored in your pipeline config
    SCANNER_VERSION="1.0.0"
    SCANNER_SHA256="<hash-from-manifest>"

    # Download script
    curl -sSL "$DEP_CONTROL_URL/api/v1/scripts/scanner.sh" -o scanner.sh

    # Verify hash BEFORE execution (Linux)
    echo "$SCANNER_SHA256  scanner.sh" | sha256sum -c -

    # Or on macOS
    echo "$SCANNER_SHA256  scanner.sh" | shasum -a 256 -c -

    # Only run if verification passed
    chmod +x scanner.sh
    ./scanner.sh sbom
    ```

    **Available commands:**
    - `sbom` - Generate and upload SBOM
    - `secrets` - Run TruffleHog secret scan
    - `sast` - Run OpenGrep/Semgrep SAST scan
    - `iac` - Run KICS IaC scan
    - `bearer` - Run Bearer privacy/security scan
    - `callgraph` - Generate and upload callgraph
    - `all` - Run all enabled scans
    """
    if script_name not in ALLOWED_SCRIPTS:
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found.",
        )

    try:
        content, version, sha256_hash = get_script_content(script_name)

        # Log version mismatch for debugging
        if v and v != version:
            logger.warning(
                f"Script {script_name} version mismatch: requested={v}, current={version}"
            )

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
        logger.error(f"Script file not found: {SCRIPTS_DIR / script_name}")
        raise HTTPException(
            status_code=404,
            detail=f"Script '{script_name}' not found on server.",
        )
    except Exception as e:
        logger.error(f"Error reading script {script_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error reading script file.",
        )


@router.get(
    "/scripts",
    summary="List Available Scripts with Hashes",
    response_model=ScriptManifest,
)
async def list_scripts() -> ScriptManifest:
    """
    List all available CI/CD scripts with their SHA256 hashes.

    Use this manifest to get the current hashes for script verification.

    **Workflow for setting up a new project:**
    1. Call this endpoint to get the current script version and hash
    2. Add the hash to your pipeline configuration
    3. Commit the pipeline to your repository

    **Workflow for updating scripts:**
    1. Check this manifest for new versions/hashes
    2. Review the changelog for the new version
    3. Update the hash in your pipeline configuration
    4. Commit the change to your repository

    This ensures you control when script updates are applied to your projects.
    """
    scripts = []

    for script_name in ALLOWED_SCRIPTS:
        try:
            _, version, sha256_hash = get_script_content(script_name)
            scripts.append(
                ScriptInfo(
                    name=script_name,
                    version=version,
                    sha256=sha256_hash,
                    url=f"/api/v1/scripts/{script_name}",
                    description="Universal scanner script for all security scans",
                )
            )
        except Exception as e:
            logger.error(f"Error getting {script_name} info: {e}")

    return ScriptManifest(
        scripts=scripts,
        verification_command_linux='echo "$SCANNER_SHA256  scanner.sh" | sha256sum -c -',
        verification_command_macos='echo "$SCANNER_SHA256  scanner.sh" | shasum -a 256 -c -',
    )
