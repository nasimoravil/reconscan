from typing import Any, Dict, List

import networkx as nx


def _guess_page_nodes(pages: List[Dict[str, Any]]) -> List[str]:
    nodes: List[str] = []
    for p in pages:
        url = p.get("url")
        if url:
            nodes.append(url)
    return nodes


def _build_relationships(root_label: str, pages: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Heuristically relate pages to API endpoints.
    - /login page -> auth endpoints
    - /dashboard page -> account/admin endpoints
    - /cart page -> payment endpoints
    """
    rels: List[Dict[str, Any]] = []

    page_paths = {}
    for p in pages:
        url = p.get("url", "")
        page_paths[url] = url

    # Fallback node for JS-only scans
    if not page_paths:
        page_paths[root_label] = root_label

    for page_url in page_paths.values():
        lower = page_url.lower()
        for ep in endpoints:
            ep_path = ep.get("path", "")
            category = ep.get("category")

            if "login" in lower and category == "auth":
                rels.append({"from": page_url, "to": ep_path, "type": "auth"})
            elif "dashboard" in lower and category in ("account", "admin"):
                rels.append({"from": page_url, "to": ep_path, "type": "dashboard"})
            elif ("cart" in lower or "checkout" in lower) and category == "payment":
                rels.append({"from": page_url, "to": ep_path, "type": "payment"})

    return rels


def build_api_graph(
    root_label: str,
    pages: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]],
    business_flows: List[Dict[str, Any]],
    fmt: str = "json",
) -> Dict[str, Any]:
    """
    Build an API surface graph with nodes and edges.
    Returns a structure that can be rendered as JSON, Graphviz DOT, or HTML.
    """
    G = nx.DiGraph()

    page_nodes = _guess_page_nodes(pages)
    for n in page_nodes:
        G.add_node(n, kind="page")

    for ep in endpoints:
        G.add_node(ep["path"], kind="endpoint", category=ep.get("category"))

    relationships = _build_relationships(root_label, pages, endpoints)
    for rel in relationships:
        G.add_edge(rel["from"], rel["to"], type=rel["type"])

    if fmt == "json":
        return {
            "nodes": [
                {"id": n, **(G.nodes[n])}
                for n in G.nodes
            ],
            "edges": [
                {"from": u, "to": v, **d}
                for u, v, d in G.edges(data=True)
            ],
            "relationships": relationships,
        }

    if fmt == "dot":
        # Simple DOT representation
        lines = ["digraph api_surface {"]
        for n, data in G.nodes(data=True):
            label = n.replace('"', '\\"')
            lines.append(f'  "{label}" [label="{label}"];')
        for u, v, d in G.edges(data=True):
            etype = d.get("type", "")
            lines.append(f'  "{u}" -> "{v}" [label="{etype}"];')
        lines.append("}")
        return {"dot": "\n".join(lines), "relationships": relationships}

    if fmt == "html":
        # Very small HTML visualization (unordered lists)
        items = []
        for rel in relationships:
            items.append(f'<li><code>{rel["from"]}</code> &rarr; <code>{rel["to"]}</code> <em>({rel["type"]})</em></li>')
        html = "<h2>API Surface Graph</h2><ul>" + "\n".join(items) + "</ul>"
        return {"html": html, "relationships": relationships}

    # Default to JSON structure
    return {
        "nodes": [
            {"id": n, **(G.nodes[n])}
            for n in G.nodes
        ],
        "edges": [
            {"from": u, "to": v, **d}
            for u, v, d in G.edges(data=True)
        ],
        "relationships": relationships,
    }

