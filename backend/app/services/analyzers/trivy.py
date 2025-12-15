import json
import tempfile
import asyncio
import os
import logging
from typing import Dict, Any
from .base import Analyzer

logger = logging.getLogger(__name__)

class TrivyAnalyzer(Analyzer):
    name = "trivy"

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        # Create a temporary file for the SBOM
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_sbom:
            json.dump(sbom, tmp_sbom)
            tmp_sbom_path = tmp_sbom.name

        target_sbom_path = tmp_sbom_path
        converted_sbom_path = None

        try:
            # Check if conversion is needed (Trivy supports CycloneDX and SPDX)
            is_cyclonedx = "bomFormat" in sbom and sbom["bomFormat"] == "CycloneDX"
            is_spdx = "spdxVersion" in sbom
            
            if not (is_cyclonedx or is_spdx):
                # Attempt to convert using Syft
                logger.info("SBOM format not natively supported by Trivy (likely Syft JSON). Attempting conversion...")
                converted_sbom_path = tmp_sbom_path + ".cdx.json"
                
                convert_process = await asyncio.create_subprocess_exec(
                    "syft",
                    "convert",
                    tmp_sbom_path,
                    "-o", "cyclonedx-json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await convert_process.communicate()
                
                if convert_process.returncode == 0:
                    # Write the converted output to file
                    with open(converted_sbom_path, "wb") as f:
                        f.write(stdout)
                    target_sbom_path = converted_sbom_path
                    logger.info("Successfully converted SBOM to CycloneDX for Trivy.")
                else:
                    logger.warning(f"Syft conversion failed: {stderr.decode()}. Proceeding with original file.")

            # Run Trivy asynchronously
            # The SBOM file is scanned
            process = await asyncio.create_subprocess_exec(
                "trivy", 
                "sbom", 
                "--format", "json", 
                "--quiet",
                target_sbom_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                logger.error(f"Trivy failed: {error_msg}")
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
            if converted_sbom_path and os.path.exists(converted_sbom_path):
                os.remove(converted_sbom_path)
