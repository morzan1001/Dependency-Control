from abc import ABC, abstractmethod
from typing import Any


class Analyzer(ABC):
    name: str

    @abstractmethod
    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        *,
        parsed_components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """On error, returns {"error": ...}."""
