"""
Vulnerable Symbols Extraction

Dynamically extracts vulnerable function/symbol names from vulnerability data.
No static database - instead parses advisory text and CVE descriptions.

Two-level approach:
1. Import-based: Check if vulnerable package is imported (reliable)
2. Symbol-based: Extract function names from CVE descriptions (heuristic)
"""

import logging
import re
from typing import Dict, List, Optional, Set

from app.schemas.enrichment import ExtractedSymbols

logger = logging.getLogger(__name__)


# Regex patterns to extract function/method names from CVE descriptions
# These patterns look for common ways functions are mentioned in advisories
SYMBOL_PATTERNS = [
    # "the function `functionName`" or "the method `methodName`"
    re.compile(
        r'(?:the\s+)?(?:function|method|procedure)\s+[`\'"]?(\w+(?:\.\w+)*)[`\'"]?',
        re.IGNORECASE,
    ),
    # "`functionName` function" or "`methodName()` method"
    re.compile(
        r'[`\'"](\w+(?:\.\w+)*)\(\)?[`\'"]?\s+(?:function|method)', re.IGNORECASE
    ),
    # "via `functionName`" or "through `methodName`"
    re.compile(
        r'(?:via|through|using|in)\s+[`\'"](\w+(?:\.\w+)*)\(\)?[`\'"]?', re.IGNORECASE
    ),
    # "calling `functionName`" or "invoking `methodName`"
    re.compile(
        r'(?:calling|invoking|executing)\s+[`\'"]?(\w+(?:\.\w+)*)\(\)?[`\'"]?',
        re.IGNORECASE,
    ),
    # "vulnerable `functionName`" or "affected `methodName`"
    re.compile(
        r'(?:vulnerable|affected|insecure)\s+[`\'"]?(\w+(?:\.\w+)*)[`\'"]?',
        re.IGNORECASE,
    ),
    # Code blocks with function calls: functionName(...) or Class.method(...)
    re.compile(r'[`\'"](\w+(?:\.\w+)*)\s*\([^)]*\)[`\'"]?', re.IGNORECASE),
    # Python/JS style: module.function or Class.method
    re.compile(r'[`\'"](\w+\.\w+(?:\.\w+)*)[`\'"]', re.IGNORECASE),
    # Java style: ClassName.methodName or package.Class.method
    re.compile(r"(?:^|\s)([A-Z]\w+\.[a-z]\w+(?:\.[a-z]\w+)*)", re.MULTILINE),
]

# Common false positives to filter out
FALSE_POSITIVE_SYMBOLS = {
    # Generic words that might match but aren't functions
    "the",
    "a",
    "an",
    "this",
    "that",
    "which",
    "where",
    "when",
    "http",
    "https",
    "www",
    "com",
    "org",
    "net",
    "io",
    "api",
    "url",
    "uri",
    "json",
    "xml",
    "html",
    "css",
    "get",
    "set",
    "put",
    "post",
    "delete",
    "patch",  # HTTP methods (context-dependent)
    "cve",
    "cwe",
    "ghsa",
    "nvd",
    "version",
    "versions",
    "update",
    "updates",
    "fix",
    "fixed",
    "patch",
    "patched",
    "null",
    "none",
    "true",
    "false",
    "undefined",
    # Too generic
    "object",
    "array",
    "string",
    "number",
    "boolean",
    "file",
    "path",
    "data",
    "value",
    "key",
    "name",
}

# Known vulnerable function patterns per ecosystem
# These are high-confidence patterns for specific vulnerability types
KNOWN_PATTERNS = {
    "prototype_pollution": [
        "merge",
        "extend",
        "assign",
        "defaults",
        "defaultsDeep",
        "set",
        "setWith",
        "zipObjectDeep",
        "mergeWith",
    ],
    "template_injection": [
        "template",
        "render",
        "compile",
        "eval",
    ],
    "command_injection": [
        "exec",
        "spawn",
        "execSync",
        "spawnSync",
        "shell",
        "system",
        "popen",
        "subprocess",
        "run",
    ],
    "sql_injection": [
        "query",
        "execute",
        "raw",
        "rawQuery",
    ],
    "path_traversal": [
        "readFile",
        "writeFile",
        "open",
        "path",
        "join",
    ],
    "deserialization": [
        "deserialize",
        "unserialize",
        "unpickle",
        "loads",
        "load",
        "readObject",
        "ObjectInputStream",
    ],
    "xxe": [
        "parse",
        "parseXML",
        "XMLParser",
        "DocumentBuilder",
    ],
    "jndi": [
        "lookup",
        "JndiLookup",
        "JndiManager",
        "InitialContext",
    ],
}


def extract_symbols_from_text(
    text: str, cve: str = "", package: str = ""
) -> ExtractedSymbols:
    """
    Extract potential vulnerable function/symbol names from advisory text.

    Uses regex patterns to find function names mentioned in CVE descriptions.
    Returns low-medium confidence results since this is heuristic-based.

    Args:
        text: CVE description or advisory text
        cve: CVE ID for reference
        package: Package name for context

    Returns:
        ExtractedSymbols with found symbols and confidence level
    """
    if not text:
        return ExtractedSymbols(cve=cve, package=package)

    found_symbols: Set[str] = set()

    # Apply all regex patterns
    for pattern in SYMBOL_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            # Normalize: lowercase, strip
            symbol = (
                match.strip().lower()
                if isinstance(match, str)
                else str(match).strip().lower()
            )

            # Filter out false positives
            base_name = symbol.split(".")[-1] if "." in symbol else symbol
            if base_name in FALSE_POSITIVE_SYMBOLS:
                continue

            # Skip very short names (likely noise)
            if len(base_name) < 3:
                continue

            # Skip if it looks like a version number
            if re.match(r"^v?\d+\.", symbol):
                continue

            found_symbols.add(symbol)

    # Check for known vulnerability patterns
    vuln_type = _detect_vulnerability_type(text)
    if vuln_type and vuln_type in KNOWN_PATTERNS:
        known_funcs = KNOWN_PATTERNS[vuln_type]
        text_lower = text.lower()
        for func in known_funcs:
            if func.lower() in text_lower:
                found_symbols.add(func.lower())

    # Determine confidence based on extraction quality
    confidence = "low"
    if len(found_symbols) > 0:
        # Higher confidence if we found symbols via known patterns
        if vuln_type:
            confidence = "medium"
        # Even higher if package name appears near function name
        if package and package.lower() in text.lower():
            confidence = "medium"

    return ExtractedSymbols(
        cve=cve,
        package=package,
        symbols=list(found_symbols),
        confidence=confidence,
        extraction_method="regex" if found_symbols else "none",
        raw_text=text[:500] if text else None,  # Store excerpt for debugging
    )


def _detect_vulnerability_type(text: str) -> Optional[str]:
    """Detect the type of vulnerability from the description."""
    text_lower = text.lower()

    if "prototype pollution" in text_lower:
        return "prototype_pollution"
    if "template injection" in text_lower or "server-side template" in text_lower:
        return "template_injection"
    if (
        "command injection" in text_lower
        or "remote code execution" in text_lower
        or "rce" in text_lower
    ):
        return "command_injection"
    if "sql injection" in text_lower or "sqli" in text_lower:
        return "sql_injection"
    if "path traversal" in text_lower or "directory traversal" in text_lower:
        return "path_traversal"
    if "deserialization" in text_lower or "insecure deserialization" in text_lower:
        return "deserialization"
    if "xxe" in text_lower or "xml external entity" in text_lower:
        return "xxe"
    if "jndi" in text_lower or "log4j" in text_lower or "log4shell" in text_lower:
        return "jndi"

    return None


def extract_symbols_from_vulnerability(vuln_data: Dict) -> ExtractedSymbols:
    """
    Extract symbols from a vulnerability object (from scanner results).

    Looks in multiple fields:
    - description / summary
    - details
    - references (sometimes contain affected functions)

    Args:
        vuln_data: Vulnerability dict from trivy/grype/osv scanner

    Returns:
        ExtractedSymbols with all found symbols
    """
    cve = vuln_data.get("id", "") or vuln_data.get("cve", "")
    package = vuln_data.get("package", "") or vuln_data.get("component", "")

    # Collect all text to parse
    text_parts = []

    # Main description fields
    for field in ["description", "summary", "details", "message", "title"]:
        if field in vuln_data and vuln_data[field]:
            text_parts.append(str(vuln_data[field]))

    # Nested details
    if "details" in vuln_data and isinstance(vuln_data["details"], dict):
        for key, value in vuln_data["details"].items():
            if isinstance(value, str):
                text_parts.append(value)

    # OSV-specific: ecosystem_specific may contain symbols
    if "ecosystem_specific" in vuln_data:
        eco = vuln_data["ecosystem_specific"]
        if isinstance(eco, dict):
            # Some OSV entries have "symbols" or "functions" directly
            if "symbols" in eco:
                symbols = eco["symbols"]
                if isinstance(symbols, list):
                    return ExtractedSymbols(
                        cve=cve,
                        package=package,
                        symbols=symbols,
                        confidence="high",
                        extraction_method="osv_ecosystem",
                    )

    # Parse combined text
    combined_text = "\n".join(text_parts)
    return extract_symbols_from_text(combined_text, cve=cve, package=package)


def get_symbols_for_finding(finding: Dict) -> ExtractedSymbols:
    """
    Extract vulnerable symbols for a finding from our scanner results.

    Looks at the finding's details.vulnerabilities array and extracts
    symbols from each vulnerability's description.

    Args:
        finding: Finding dict with details.vulnerabilities

    Returns:
        Combined ExtractedSymbols from all vulnerabilities
    """
    component = finding.get("component", "")

    all_symbols: Set[str] = set()
    all_cves: List[str] = []
    best_confidence = "low"
    extraction_method = "none"

    # Get vulnerabilities from the finding
    details = finding.get("details", {})
    vulnerabilities = details.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")
        if vuln_id:
            all_cves.append(vuln_id)

        # Extract symbols from this vulnerability
        extracted = extract_symbols_from_vulnerability(vuln)

        if extracted.symbols:
            all_symbols.update(extracted.symbols)

            # Track best confidence
            if extracted.confidence == "high":
                best_confidence = "high"
            elif extracted.confidence == "medium" and best_confidence == "low":
                best_confidence = "medium"

            if extracted.extraction_method != "none":
                extraction_method = extracted.extraction_method

    return ExtractedSymbols(
        cve=",".join(all_cves) if all_cves else "",
        package=component,
        symbols=list(all_symbols),
        confidence=best_confidence,
        extraction_method=extraction_method,
    )
