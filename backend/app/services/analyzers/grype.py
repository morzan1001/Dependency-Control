import asyncio
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from .base import Analyzer


class GrypeAnalyzer(Analyzer):
    name = "grype"

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=False
        ) as tmp_sbom:
            json.dump(sbom, tmp_sbom)
            tmp_sbom_path = tmp_sbom.name

        try:
            # Run Grype
            process = await asyncio.create_subprocess_exec(
                "grype",
                f"sbom:{tmp_sbom_path}",
                "-o",
                "json",
                "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"error": "Grype analysis failed", "details": stderr.decode()}

            try:
                output_str = stdout.decode()
                if not output_str.strip():
                    return {"matches": []}

                grype_result = json.loads(output_str)
                return grype_result
            except json.JSONDecodeError:
                return {"error": "Invalid JSON output from Grype"}

        except Exception as e:
            return {"error": f"Exception during Grype analysis: {str(e)}"}

        finally:
            if os.path.exists(tmp_sbom_path):
                os.remove(tmp_sbom_path)
