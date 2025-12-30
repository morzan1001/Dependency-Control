"""Schemas for CI/CD scripts API."""

from pydantic import BaseModel


class ScriptInfo(BaseModel):
    """Information about a script including its hash for verification."""

    name: str
    version: str
    sha256: str
    url: str
    description: str


class ScriptManifest(BaseModel):
    """Manifest containing all available scripts with their hashes."""

    scripts: list[ScriptInfo]
    verification_command_linux: str
    verification_command_macos: str
