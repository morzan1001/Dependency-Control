import json
import tempfile
import asyncio
import os
from typing import Dict, Any
from .base import Analyzer

class TrivyAnalyzer(Analyzer):
    name = "trivy"

    async def analyze(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        # Create a temporary file for the SBOM
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_sbom:
            json.dump(sbom, tmp_sbom)
            tmp_sbom_path = tmp_sbom.name

        try:
            # Run Trivy asynchronously
            # The SBOM file is scanned
            process = await asyncio.create_subprocess_exec(
                "trivy", 
                "sbom", 
                "--format", "json", 
                "--quiet",
                tmp_sbom_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                print(f"Trivy failed: {error_msg}")
                return {"error": "Trivy analysis failed", "details": error_msg}
            
            try:
                output_str = stdout.decode()
                if not output_str.strip():
                     return {"results": []} # Empty result
                
                trivy_result = json.loads(output_str)
                return trivy_result
            except json.JSONDecodeError:
                return {"error": "Invalid JSON output from Trivy", "output": output_str}

        except Exception as e:
            return {"error": f"Exception during Trivy analysis: {str(e)}"}

        finally:
            # Cleanup
            if os.path.exists(tmp_sbom_path):
                os.remove(tmp_sbom_path)
