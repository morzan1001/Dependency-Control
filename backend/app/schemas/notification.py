import re

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field, field_validator

# Names the UI and syft use for an ecosystem, mapped to its purl type.
_ECOSYSTEM_ALIASES = {"pip": "pypi", "python": "pypi", "go": "golang", "go-module": "golang", "dotnet": "nuget"}
# Dependency types a purl-less row of the ecosystem is stored under, besides the purl type itself.
ECOSYSTEM_STORED_TYPES = {"pypi": {"python"}, "golang": {"go-module"}, "maven": {"java-archive"}, "nuget": {"dotnet"}}
# The types the purl spec registers; a rule typed otherwise could never match a dependency.
_PURL_TYPES = frozenset(
    {
        "alpm",
        "apk",
        "bitbucket",
        "bitnami",
        "cargo",
        "cocoapods",
        "composer",
        "conan",
        "conda",
        "cpan",
        "cran",
        "deb",
        "docker",
        "gem",
        "generic",
        "github",
        "golang",
        "hackage",
        "hex",
        "huggingface",
        "luarocks",
        "maven",
        "mlflow",
        "npm",
        "nuget",
        "oci",
        "pub",
        "pypi",
        "qpm",
        "rpm",
        "swid",
        "swift",
    }
)
_RELEASE = re.compile(r"[vV]?(\d+(?:\.\d+)*)")
_WILDCARD_SEGMENT = re.compile(r"(^|[.-])[xX*](\.|$)")


def _release(version: str) -> tuple[int, ...] | None:
    """The leading numeric release, epoch dropped and trailing zeros trimmed: 1:4.1.0.Final -> (4, 1)."""
    match = _RELEASE.match(version.strip().split(":", 1)[-1])
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


class AdvisoryPackage(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        description="Affected package: its name, or qualified as group:artifact, @scope/name or a module path",
    )
    version: str | None = Field(None, description="Affected version (inclusive max)")
    type: str | None = Field(None, description="Ecosystem as a purl type (npm, pypi, maven, golang, nuget...)")

    @field_validator("type")
    @classmethod
    def _purl_type(cls, value: str | None) -> str | None:
        if not value or not value.strip():
            return None
        value = value.strip().lower()
        value = _ECOSYSTEM_ALIASES.get(value, value)
        if value not in _PURL_TYPES:
            raise ValueError(f"'{value}' is not a purl type")
        return value

    @field_validator("version")
    @classmethod
    def _comparable_bound(cls, value: str | None) -> str | None:
        if not value or not value.strip():
            return None
        value = value.strip()
        if _release(value) is None or _WILDCARD_SEGMENT.search(value):
            raise ValueError(f"'{value}' names no version to compare against")
        return value

    def covers(self, version: str) -> bool | None:
        """Whether ``version`` is at or below this rule's inclusive max version; None if it cannot be compared."""
        if self.version is None:
            return True
        try:
            return Version(version) <= Version(self.version)
        except InvalidVersion:
            # Other schemes compare by numeric release, so a qualifier (.Final, -SNAPSHOT) never lifts a
            # version past its own release.
            installed = _release(version)
            return None if installed is None else installed <= (_release(self.version) or ())


class BroadcastRequest(BaseModel):
    type: str = Field(..., description="Type of message: 'general' or 'advisory'")
    target_type: str = Field(..., description="Target audience: 'global', 'teams', 'advisory'")
    target_teams: list[str] | None = Field(None, description="List of Team IDs if target_type is 'teams'")
    channels: list[str] | None = Field(None, description="Channels to send to (email, slack, mattermost)")

    # For Advisory
    packages: list[AdvisoryPackage] | None = Field(None, description="List of affected packages for advisory")

    subject: str
    message: str
    dry_run: bool = Field(False, description="If true, only calculates impact without sending")


class BroadcastResult(BaseModel):
    recipient_count: int
    project_count: int = 0
    unique_user_count: int = 0
    uncomparable_versions: list[str] = Field(
        default_factory=list,
        description="Matched dependencies whose version could not be compared with the max version; "
        "their projects are not counted, and their admins are told the version could not be compared",
    )


class BroadcastHistoryItem(BaseModel):
    id: str
    type: str
    target_type: str
    subject: str
    created_at: str
    created_by: str | None = None
    recipient_count: int
    project_count: int
    unique_user_count: int = 0
    teams: list[str] | None = None


class PackageSuggestions(BaseModel):
    """Head of the alphabetical matches for a typeahead query."""

    names: list[str] = Field(..., description="Alphabetical, at most the endpoint's suggestion limit")
    more: bool = Field(
        ...,
        description="More packages match than are listed; the query has to narrow to reach them",
    )


# The alert's priority bucket, as every channel labels it.
PRIORITY_VULNS_LABEL = "Priority (Critical/High/KEV/High EPSS)"


class AlertVulnerability(BaseModel):
    """One vulnerability line in a "vulnerabilities found" alert.

    Declares the field names every channel formatter reads. Defaults are tolerant because the
    Teams card is built from a webhook payload that has been through JSON.
    """

    id: str = Field("Unknown", description="CVE or advisory identifier")
    severity: str = Field("UNKNOWN", description="Severity of the vulnerability")
    package: str = Field("Unknown", description="Component the vulnerability was found in")
    version: str = Field("", description="Version of the component")
    in_kev: bool = False
    epss_score: float | None = None
    kev_due_date: str | None = None
    kev_ransomware_use: bool = False
