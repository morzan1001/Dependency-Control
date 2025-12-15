import httpx
import logging
from typing import Dict, Any, Set
from datetime import datetime, timedelta
from .base import Analyzer
import difflib

logger = logging.getLogger(__name__)

class TyposquattingAnalyzer(Analyzer):
    name = "typosquatting"
    
    # Cache for popular packages
    _popular_packages_cache: Dict[str, Set[str]] = {
        "pypi": set(),
        "npm": set()
    }
    _last_update: datetime = None
    _cache_ttl = timedelta(hours=24)

    async def _ensure_popular_packages(self):
        now = datetime.utcnow()
        if self._last_update and (now - self._last_update) < self._cache_ttl:
            if self._popular_packages_cache["pypi"] and self._popular_packages_cache["npm"]:
                return

        logger.info("Updating popular packages list for Typosquatting detection...")
        
        async with httpx.AsyncClient() as client:
            # 1. PyPI - Top 5000
            try:
                # Source: https://github.com/hugovk/top-pypi-packages
                resp = await client.get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json")
                if resp.status_code == 200:
                    data = resp.json()
                    # data["rows"] is list of {"project": "name", ...}
                    packages = {row["project"].lower() for row in data.get("rows", [])[:5000]}
                    self._popular_packages_cache["pypi"] = packages
                    logger.info(f"Loaded {len(packages)} popular PyPI packages.")
            except Exception as e:
                logger.error(f"Failed to fetch PyPI top packages: {e}")
                # Fallback to static list if empty
                if not self._popular_packages_cache["pypi"]:
                    self._popular_packages_cache["pypi"] = self._get_static_pypi()

            # 2. NPM
            # Use static list for NPM as no clean top list API is available
            if not self._popular_packages_cache["npm"]:
                 self._popular_packages_cache["npm"] = self._get_static_npm()

        self._last_update = now

    def _get_static_pypi(self) -> Set[str]:
        return {
            "requests", "flask", "django", "numpy", "pandas", "boto3", "urllib3", 
            "botocore", "typing-extensions", "python-dateutil", "setuptools", "pip",
            "wheel", "certifi", "idna", "charset-normalizer", "aiohttp", "pydantic",
            "fastapi", "uvicorn", "sqlalchemy", "pytest", "docker", "kubernetes"
        }

    def _get_static_npm(self) -> Set[str]:
        return {
            "react", "react-dom", "lodash", "express", "axios", "moment", "tslib",
            "commander", "chalk", "debug", "inquirer", "async", "bluebird", "uuid",
            "classnames", "prop-types", "vue", "angular", "next", "webpack",
            "eslint", "prettier", "babel", "jest", "rxjs", "yargs", "body-parser",
            "cors", "dotenv", "jsonwebtoken", "mongoose", "socket.io", "redis",
            "aws-sdk", "typescript", "fs-extra", "mkdirp", "glob", "minimist"
        }

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        await self._ensure_popular_packages()
        
        components = self._get_components(sbom)
        issues = []

        for component in components:
            name = component.get("name", "").lower()
            purl = component.get("purl", "")
            
            # Determine ecosystem
            ecosystem = "unknown"
            if purl.startswith("pkg:pypi/") or component.get("type") == "python":
                ecosystem = "pypi"
            elif purl.startswith("pkg:npm/") or component.get("type") == "npm":
                ecosystem = "npm"
            
            if ecosystem not in self._popular_packages_cache:
                continue
                
            popular_list = self._popular_packages_cache[ecosystem]
            
            # If the package itself is in the popular list, it's likely fine
            if name in popular_list:
                continue 
                
            # Check against popular packages
            for popular in popular_list:
                # Optimization: Skip if length difference is too big
                if abs(len(name) - len(popular)) > 2:
                    continue

                # Calculate similarity
                ratio = difflib.SequenceMatcher(None, name, popular).ratio()
                
                if ratio > 0.82: # Slightly increased threshold
                    if self._is_suspicious(name, popular):
                        issues.append({
                            "component": component.get("name"),
                            "version": component.get("version"),
                            "purl": purl,
                            "imitated_package": popular,
                            "similarity": round(ratio, 2)
                        })

        return {"typosquatting_issues": issues}

    def _is_suspicious(self, name: str, popular: str) -> bool:
        # Heuristic:
        # 1. Length difference is small
        if abs(len(name) - len(popular)) > 2:
            return False
            
        # 2. Not a prefix/suffix (e.g. "react-dom" vs "react" is fine)
        if name.startswith(popular) or popular.startswith(name):
            return False
            
        return True
