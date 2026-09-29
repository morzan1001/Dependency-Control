import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Iterable
from typing import Any


def normalize_hash_algorithm(alg: str) -> str:
    """Normalize a hash algorithm name (lowercase, no hyphens): "SHA-256" -> "sha256"."""
    if not alg:
        return ""
    return alg.lower().replace("-", "")


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


async def gather_bounded[T, R](
    items: Iterable[T], worker: Callable[[T], Awaitable[R]], limit: int
) -> list[R | BaseException]:
    """Run ``worker`` over ``items`` with at most ``limit`` in flight; a failure stays in its item's slot."""
    semaphore = asyncio.Semaphore(limit)

    async def bounded(item: T) -> R:
        async with semaphore:
            return await worker(item)

    return await asyncio.gather(*(bounded(item) for item in items), return_exceptions=True)
