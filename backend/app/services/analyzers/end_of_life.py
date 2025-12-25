import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import httpx

from app.core.cache import cache_service, CacheKeys, CacheTTL
from .base import Analyzer

logger = logging.getLogger(__name__)

# Mapping from package/component names to endoflife.date product IDs
# See https://endoflife.date/api for all available products
NAME_TO_EOL_MAPPING = {
    # Programming Languages & Runtimes
    "python": "python",
    "python3": "python",
    "cpython": "python",
    "node": "nodejs",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "go": "go",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
    "java": "java",
    "openjdk": "java",
    "dotnet": "dotnet",
    "dotnet-runtime": "dotnet",
    "dotnet-sdk": "dotnet",
    ".net": "dotnet",
    "rust": "rust",
    "perl": "perl",
    "swift": "swift",
    "kotlin": "kotlin",
    "elixir": "elixir",
    "erlang": "erlang",
    # Databases
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "pg": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "opensearch": "opensearch",
    "sqlite": "sqlite",
    "cassandra": "apache-cassandra",
    "couchdb": "couchdb",
    "neo4j": "neo4j",
    # Web Servers & Proxies
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "tomcat": "apache-tomcat",
    "traefik": "traefik",
    "haproxy": "haproxy",
    "envoy": "envoy",
    # Container & Orchestration
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "docker": "docker",
    "containerd": "containerd",
    "podman": "podman",
    "helm": "helm",
    # Operating Systems
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "rocky-linux": "rocky-linux",
    "almalinux": "almalinux",
    "alpine": "alpine",
    "fedora": "fedora",
    "amazon-linux": "amazon-linux",
    "opensuse": "opensuse",
    "sles": "sles",
    "windows-server": "windows-server",
    # Frontend Frameworks
    "angular": "angular",
    "@angular/core": "angular",
    "react": "react",
    "react-dom": "react",
    "vue": "vuejs",
    "vue.js": "vuejs",
    "vuejs": "vuejs",
    "svelte": "svelte",
    "next": "nextjs",
    "nextjs": "nextjs",
    "next.js": "nextjs",
    "nuxt": "nuxt",
    "nuxt.js": "nuxt",
    "gatsby": "gatsby",
    "ember": "emberjs",
    "jquery": "jquery",
    # Backend Frameworks
    "django": "django",
    "flask": "flask",
    "fastapi": "fastapi",
    "rails": "rails",
    "ruby-on-rails": "rails",
    "spring-framework": "spring-framework",
    "spring-boot": "spring-boot",
    "spring": "spring-framework",
    "laravel": "laravel",
    "symfony": "symfony",
    "express": "nodejs",
    "nestjs": "nestjs",
    "fastify": "fastify",
    "gin": "gin",
    "echo": "echo",
    "actix": "actix-web",
    # Build Tools & Package Managers
    "npm": "npm",
    "yarn": "yarn",
    "pnpm": "pnpm",
    "pip": "pip",
    "maven": "maven",
    "gradle": "gradle",
    "composer": "composer",
    "bundler": "bundler",
    "cargo": "cargo",
    # Cloud & Infrastructure
    "terraform": "terraform",
    "ansible": "ansible",
    "pulumi": "pulumi",
    "vagrant": "vagrant",
    "packer": "packer",
    "vault": "hashicorp-vault",
    "consul": "consul",
    # Message Queues
    "rabbitmq": "rabbitmq",
    "kafka": "apache-kafka",
    "activemq": "apache-activemq",
    "nats": "nats-server",
    # ML/AI Frameworks
    "tensorflow": "tensorflow",
    "pytorch": "pytorch",
    "keras": "keras",
    "scikit-learn": "scikit-learn",
    "pandas": "pandas",
    "numpy": "numpy",
    # Other Tools
    "grafana": "grafana",
    "prometheus": "prometheus",
    "kibana": "kibana",
    "logstash": "logstash",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "github-enterprise": "github-enterprise-server",
    "kong": "kong-gateway",
    "istio": "istio",
    "linkerd": "linkerd",
}

# Alias for backward compatibility
CPE_TO_EOL_MAPPING = NAME_TO_EOL_MAPPING


class EndOfLifeAnalyzer(Analyzer):
    name = "end_of_life"
    api_url = "https://endoflife.date/api"

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Dict[str, Any] = None,
        parsed_components: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results = []
        checked_products: Set[str] = set()  # Avoid duplicate API calls

        # Collect all unique products to check
        products_to_check: Dict[str, tuple] = {}  # product -> (component_name, version)
        
        for component in components:
            name = component.get("name", "").lower()
            version = component.get("version", "")
            cpes = component.get("cpes") or component.get("_cpes") or []

            eol_products = self._extract_products_from_cpes(cpes)
            if not eol_products:
                mapped = CPE_TO_EOL_MAPPING.get(name)
                if mapped:
                    eol_products.add(mapped)
                else:
                    eol_products.add(name)

            for product in eol_products:
                if product not in products_to_check:
                    products_to_check[product] = (component.get("name"), version)

        # Check cache for all products first
        cache_keys = [CacheKeys.eol(product) for product in products_to_check.keys()]
        cached_data = await cache_service.mget(cache_keys) if cache_keys else {}
        
        products_to_fetch = []
        for product, (comp_name, version) in products_to_check.items():
            cache_key = CacheKeys.eol(product)
            if cache_key in cached_data and cached_data[cache_key] is not None:
                cycles = cached_data[cache_key]
                if cycles:  # Not a negative cache entry
                    eol_info = self._check_version(version, cycles)
                    if eol_info:
                        results.append({
                            "component": comp_name,
                            "version": version,
                            "product": product,
                            "eol_info": eol_info,
                        })
            else:
                products_to_fetch.append((product, comp_name, version))

        logger.debug(f"EOL: {len(products_to_check) - len(products_to_fetch)} from cache, {len(products_to_fetch)} to fetch")

        # Fetch uncached products
        if products_to_fetch:
            async with httpx.AsyncClient(timeout=10.0) as client:
                to_cache = {}
                for product, comp_name, version in products_to_fetch:
                    try:
                        response = await client.get(f"{self.api_url}/{product}.json")
                        if response.status_code == 200:
                            cycles = response.json()
                            # Cache the EOL data
                            to_cache[CacheKeys.eol(product)] = cycles
                            
                            eol_info = self._check_version(version, cycles)
                            if eol_info:
                                results.append({
                                    "component": comp_name,
                                    "version": version,
                                    "product": product,
                                    "eol_info": eol_info,
                                })
                        elif response.status_code == 404:
                            # Cache negative result
                            to_cache[CacheKeys.eol(product)] = []
                    except Exception as e:
                        logger.debug(f"EOL check failed for {product}: {e}")
                        continue
                
                # Batch cache all fetched results
                if to_cache:
                    await cache_service.mset(to_cache, CacheTTL.EOL_STATUS)

        return {"eol_issues": results}

    def _extract_products_from_cpes(self, cpes: List[str]) -> Set[str]:
        """Extract product names from CPE strings and map to endoflife.date IDs."""
        products = set()

        for cpe in cpes:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            # or cpe:/a:vendor:product:version:...
            match = re.match(r"cpe:[:/]2\.3:a:([^:]+):([^:]+)", cpe)
            if not match:
                match = re.match(r"cpe:/a:([^:]+):([^:]+)", cpe)

            if match:
                vendor = match.group(1).lower()
                product = match.group(2).lower()

                # Try product directly
                if product in CPE_TO_EOL_MAPPING:
                    products.add(CPE_TO_EOL_MAPPING[product])
                # Try vendor:product combo
                elif f"{vendor}_{product}" in CPE_TO_EOL_MAPPING:
                    products.add(CPE_TO_EOL_MAPPING[f"{vendor}_{product}"])
                # Try just product name
                else:
                    products.add(product)

        return products

    def _check_version(
        self, version: str, cycles: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Check if a version matches an EOL cycle."""
        if not version:
            return None

        # Clean version string
        clean_version = version.lstrip("v").lower()

        for cycle in cycles:
            cycle_version = str(cycle.get("cycle", ""))

            # Check various matching strategies
            if self._version_matches_cycle(clean_version, cycle_version):
                eol = cycle.get("eol")

                # eol can be: date string, True (already EOL), False (not EOL)
                if eol is True:
                    return cycle
                elif eol and eol is not False:
                    try:
                        eol_date = datetime.strptime(str(eol), "%Y-%m-%d")
                        if eol_date < datetime.now():
                            return cycle
                    except ValueError:
                        pass
        return None

    def _version_matches_cycle(self, version: str, cycle: str) -> bool:
        """Check if a version belongs to a cycle."""
        if not version or not cycle:
            return False

        # Direct match
        if version == cycle:
            return True

        # Version starts with cycle (e.g., "3.8.5" matches cycle "3.8")
        if version.startswith(f"{cycle}."):
            return True

        # Major version match (e.g., "3" matches "3.x")
        if "." in version:
            major = version.split(".")[0]
            if cycle == major:
                return True
            # Check major.minor match
            if version.count(".") >= 1:
                major_minor = ".".join(version.split(".")[:2])
                if cycle == major_minor:
                    return True

        return False
