from pydantic import BaseModel


class ScriptInfo(BaseModel):
    name: str
    version: str
    sha256: str
    url: str
    description: str


class ScriptManifest(BaseModel):
    scripts: list[ScriptInfo]
    verification_command_linux: str
    verification_command_macos: str
