from abc import ABC, abstractmethod
from typing import Any


class Analyzer(ABC):
    """Base class for all SBOM analyzers; on error, analyze() returns a dict with an "error" key."""

    name: str

    @abstractmethod
    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Analyze an SBOM for security issues; on error returns {"error": ...}."""
