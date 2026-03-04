import re
from typing import Dict, List, Any

import esprima


ENDPOINT_REGEXES = [
    re.compile(r'["\'](/api/[A-Za-z0-9_\-/]+)["\']'),
    re.compile(r'["\'](/graphql[^"\']*)["\']'),
    re.compile(r'["\'](/internal/[A-Za-z0-9_\-/]+)["\']'),
]

WS_REGEX = re.compile(r'["\'](wss?://[A-Za-z0-9_\-.:/]+)["\']')
DOMAIN_REGEX = re.compile(r'["\']([A-Za-z0-9_\-]+\.internal\.[A-Za-z0-9\-.]+)["\']')
TECH_REGEXES = {
    "jQuery 3.4.1": re.compile(r"jQuery\s*3\.4\.1"),
    "React": re.compile(r"react\.js", re.I),
}


def _extract_literals_with_ast(code: str) -> List[str]:
    literals: List[str] = []
    try:
        tree = esprima.parseScript(code, tolerant=True)
    except Exception:
        return literals

    def visit(node: Any) -> None:
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
    """
    Parse JavaScript sources using regex + AST literal extraction.
    Returns a dict with:
      - endpoints: list of {source, path, type}
      - websockets: list of {source, url}
      - infra: list of {source, host}
      - technologies: list of detected technology strings
      - literals: collected string literals for downstream analysis
    """
    endpoints: List[Dict[str, Any]] = []
    websockets: List[Dict[str, Any]] = []
    infra: List[Dict[str, Any]] = []
    technologies: List[str] = []
    technology_hits: List[Dict[str, Any]] = []
    literals_all: List[str] = []

    for src_name, code in js_sources.items():
        # Regex-based endpoint extraction
        for regex in ENDPOINT_REGEXES:
            for m in regex.finditer(code):
                path = m.group(1)
                ep_type = "graphql" if "graphql" in path else "rest"
                endpoints.append({"source": src_name, "path": path, "type": ep_type})

        for m in WS_REGEX.finditer(code):
            websockets.append({"source": src_name, "url": m.group(1)})

        for m in DOMAIN_REGEX.finditer(code):
            infra.append({"source": src_name, "host": m.group(1)})

        # Technology markers
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

