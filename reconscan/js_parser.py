"""JavaScript source code parsing and pattern extraction module.

Extracts indicators from JavaScript source code including:
- API endpoints (REST and GraphQL)
- WebSocket connections
- Infrastructure references (internal services, domains)
- Technology detection (frameworks, libraries)
- String literals (for secret scanning)

Uses a hybrid approach:
- Regular expressions for fast pattern matching
- Esprima AST parser for accurate string literal extraction
"""

import re
from typing import Dict, List, Any

import esprima


# API endpoint patterns - matches /api/*, /graphql, /internal/*
ENDPOINT_REGEXES = [
    re.compile(r'["\'](/api/[A-Za-z0-9_\-/]+)["\']'),
    re.compile(r'["\'](/graphql[^"\']*)["\']'),
    re.compile(r'["\'](/internal/[A-Za-z0-9_\-/]+)["\']'),
]

# WebSocket connection patterns
WS_REGEX = re.compile(r'["\'](wss?://[A-Za-z0-9_\-.:/]+)["\']')

# Internal infrastructure/domain patterns
DOMAIN_REGEX = re.compile(r'["\']([A-Za-z0-9_\-]+\.internal\.[A-Za-z0-9\-.]+)["\']')

# Technology detection patterns (expandable)
TECH_REGEXES = {
    "jQuery 3.4.1": re.compile(r"jQuery\s*3\.4\.1"),
    "React": re.compile(r"react\.js", re.I),
}


def _extract_literals_with_ast(code: str) -> List[str]:
    """Extract all string literals from JavaScript code using AST parsing.
    
    Uses the Esprima JavaScript parser to accurately identify all string literals
    in the code, which are then used for secret and pattern detection.
    
    Args:
        code: JavaScript source code to parse
    
    Returns:
        List of string literal values found in the code
    
    Note:
        If parsing fails, returns empty list. Parser is set to 'tolerant' mode
        to handle syntax errors gracefully.
    """
    literals: List[str] = []
    try:
        tree = esprima.parseScript(code, tolerant=True)
    except Exception:
        return literals

    def visit(node: Any) -> None:
        """Recursively visit AST nodes to find Literal nodes."""
        if isinstance(node, dict):
            if node.get("type") == "Literal" and isinstance(node.get("value"), str):
                literals.append(node["value"])
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(tree.toDict() if hasattr(tree, "toDict") else tree)
    return literals


def parse_js_sources(js_sources: Dict[str, str]) -> Dict[str, Any]:
    """Parse multiple JavaScript source files and extract reconnaissance data.

    Performs pattern matching and AST parsing on provided JavaScript code to extract:
    - API endpoints (REST and GraphQL)
    - WebSocket connections  
    - Infrastructure references
    - Technology detection
    - String literals for downstream analysis

    Processing per source:
    1. Regex-based extraction of endpoints, WebSockets, and infra
    2. Technology detection via pattern matching
    3. AST-based extraction of all string literals

    Args:
        js_sources: Dictionary mapping source names to JavaScript code strings
            Example: {'app.js': 'const x = fetch(...)', 'main.js': '...'}

    Returns:
        Dictionary containing parsed data:
        - endpoints: List of discovered API endpoints with source and type
        - websockets: List of WebSocket connections discovered
        - infra: List of infrastructure/internal domain references
        - technologies: List of detected technology names
        - technology_hits: List of detection matches with evidence
        - literals: All string literals from all sources combined
    """
    endpoints: List[Dict[str, Any]] = []
    websockets: List[Dict[str, Any]] = []
    infra: List[Dict[str, Any]] = []
    technologies: List[str] = []
    technology_hits: List[Dict[str, Any]] = []
    literals_all: List[str] = []

    for src_name, code in js_sources.items():
        # Extract API endpoints using regex patterns
        for regex in ENDPOINT_REGEXES:
            for m in regex.finditer(code):
                path = m.group(1)
                ep_type = "graphql" if "graphql" in path else "rest"
                endpoints.append({"source": src_name, "path": path, "type": ep_type})

        # Extract WebSocket connections
        for m in WS_REGEX.finditer(code):
            websockets.append({"source": src_name, "url": m.group(1)})

        # Extract internal infrastructure references
        for m in DOMAIN_REGEX.finditer(code):
            infra.append({"source": src_name, "host": m.group(1)})

        # Detect technologies via pattern matching
        for tech, tre in TECH_REGEXES.items():
            m = tre.search(code)
            if m:
                if tech not in technologies:
                    technologies.append(tech)
                technology_hits.append(
                    {
                        "technology": tech,
                        "source": src_name,
                        "evidence": m.group(0)[:200],
                    }
                )

        # Extract all string literals for secret detection
        literals = _extract_literals_with_ast(code)
        literals_all.extend(literals)

    return {
        "endpoints": endpoints,
        "websockets": websockets,
        "infra": infra,
        "technologies": technologies,
        "technology_hits": technology_hits,
        "literals": literals_all,
    }

