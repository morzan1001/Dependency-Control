import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.services.aggregation.versions import parse_version_key

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
_RELEASE = re.compile(r"[vV]?\d")
_WILDCARD_SEGMENT = re.compile(r"(^|[.-])[xX*](\.|$)")


def _names_release(version: str) -> bool:
    """Whether the version, epoch dropped, starts at a numeric release."""
    return _RELEASE.match(version.strip().split(":", 1)[-1]) is not None


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
        if not _names_release(value) or _WILDCARD_SEGMENT.search(value):
            raise ValueError(f"'{value}' names no version to compare against")
        return value

    def covers(self, version: str) -> bool | None:
        """Whether ``version`` is at or below this rule's inclusive max version; None if it names no release."""
        if self.version is None:
            return True
        if not _names_release(version):
            return None
        return parse_version_key(version) <= parse_version_key(self.version)


class BroadcastRequest(BaseModel):
    target_type: Literal["global", "teams", "advisory"] = Field(..., description="Target audience")
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


def scan_alert_level(critical: int, high: int) -> Literal["critical", "warning", "ok"]:
    if critical:
        return "critical"
    return "warning" if high else "ok"


class AlertVulnerability(BaseModel):
    """One vulnerability line of an alert; lenient defaults because the Teams card reads the untyped webhook payload."""

    id: str = Field("Unknown", description="CVE or advisory identifier")
    severity: str = Field("UNKNOWN", description="Severity of the vulnerability")
    package: str = Field("Unknown", description="Component the vulnerability was found in")
    version: str = Field("", description="Version of the component")
    in_kev: bool = False
    epss_score: float | None = None
    kev_due_date: str | None = None
    kev_ransomware_use: bool = False

    @property
    def versioned_package(self) -> str:
        return f"{self.package}@{self.version}" if self.version else self.package

    @property
    def tags(self) -> list[str]:
        tags = ["KEV"] if self.in_kev else []
        if self.epss_score:
            tags.append(f"EPSS: {self.epss_score:.1%}")
        return tags
