from abc import ABC, abstractmethod
from typing import Dict, Any

class Analyzer(ABC):
    name: str

    @abstractmethod
    async def analyze(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        pass
