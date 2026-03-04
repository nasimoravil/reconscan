from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .crawler import crawl_site
from .js_collector import collect_js_from_html, download_js_urls
from .js_parser import parse_js_sources
from .endpoint_extractor import classify_endpoints
from .auth_detector import detect_auth_flows
from .secret_scanner import detect_secrets
from .header_analyzer import analyze_headers
from .vulnerability_matcher import match_vulnerabilities
from .behavior_probe import probe_endpoints
from .business_logic_detector import detect_business_flows
from .api_graph import build_api_graph
from .report_generator import generate_report


@dataclass
class ReconConfig:
    enable_behavior_probe: bool = False
    graph_format: str = "json"  # json | dot | html
    report_format: str = "json"  # json | md | html
    max_pages: int = 100
    timeout: int = 10


@dataclass
class ReconResult:
    target: str
    technologies: List[str] = field(default_factory=list)
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, Any] = field(default_factory=dict)
    auth_flows: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    infra: List[Dict[str, Any]] = field(default_factory=list)
    vulns: List[Dict[str, Any]] = field(default_factory=list)
    behavior: List[Dict[str, Any]] = field(default_factory=list)
    business_flows: List[Dict[str, Any]] = field(default_factory=list)
    api_graph: Dict[str, Any] = field(default_factory=dict)
    risks: List[Dict[str, Any]] = field(default_factory=list)
    technology_hits: List[Dict[str, Any]] = field(default_factory=list)


class ReconEngine:
    def __init__(self, config: Optional[ReconConfig] = None) -> None:
        self.config = config or ReconConfig()

    # 1) Domain scanning pipeline
    def scan_domain(self, url: str) -> ReconResult:
        pages, responses = crawl_site(url, max_pages=self.config.max_pages, timeout=self.config.timeout)

        js_urls = collect_js_from_html(pages, base_url=url)
        js_sources = download_js_urls(js_urls, timeout=self.config.timeout)

        parsed = parse_js_sources(js_sources)

        endpoints, infra, technologies = classify_endpoints(parsed)
        technology_hits = parsed.get("technology_hits", [])
        auth_flows = detect_auth_flows(parsed, endpoints)
        secrets = detect_secrets(parsed)
        headers = analyze_headers(responses)
        vulns = match_vulnerabilities(technologies, technology_hits=technology_hits)

        behavior = []
        if self.config.enable_behavior_probe:
            behavior = probe_endpoints(url, endpoints, timeout=self.config.timeout)

        business_flows = detect_business_flows(endpoints)
        api_graph = build_api_graph(url, pages, endpoints, business_flows, fmt=self.config.graph_format)

        from .risk_engine import compute_risks

        risks = compute_risks(secrets, endpoints, behavior, business_flows, vulns=vulns, headers_summary=headers)

        return ReconResult(
            target=url,
            technologies=technologies,
            endpoints=endpoints,
            headers=headers,
            auth_flows=auth_flows,
            secrets=secrets,
            infra=infra,
            vulns=vulns,
            behavior=behavior,
            business_flows=business_flows,
            api_graph=api_graph,
            risks=risks,
            technology_hits=technology_hits,
        )

    # 2) JS-only pipelines
    def scan_js_file(self, path: str) -> ReconResult:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        return self.scan_js_snippet(code, label=path)

    def scan_js_urls(self, urls: List[str]) -> ReconResult:
        js_sources = download_js_urls(urls, timeout=self.config.timeout)
        parsed = parse_js_sources(js_sources)
        endpoints, infra, technologies = classify_endpoints(parsed)
        technology_hits = parsed.get("technology_hits", [])
        auth_flows = detect_auth_flows(parsed, endpoints)
        secrets = detect_secrets(parsed)
        vulns = match_vulnerabilities(technologies, technology_hits=technology_hits)

        business_flows = detect_business_flows(endpoints)
        api_graph = build_api_graph("js-list", [], endpoints, business_flows, fmt=self.config.graph_format)

        from .risk_engine import compute_risks

        risks = compute_risks(secrets, endpoints, [], business_flows, vulns=vulns, headers_summary={})

        return ReconResult(
            target="js-list",
            technologies=technologies,
            endpoints=endpoints,
            headers={},
            auth_flows=auth_flows,
            secrets=secrets,
            infra=infra,
            vulns=vulns,
            behavior=[],
            business_flows=business_flows,
            api_graph=api_graph,
            risks=risks,
            technology_hits=technology_hits,
        )

    def scan_js_snippet(self, code: str, label: str = "stdin") -> ReconResult:
        js_sources = {label: code}
        parsed = parse_js_sources(js_sources)

        endpoints, infra, technologies = classify_endpoints(parsed)
        technology_hits = parsed.get("technology_hits", [])
        auth_flows = detect_auth_flows(parsed, endpoints)
        secrets = detect_secrets(parsed)
        vulns = match_vulnerabilities(technologies, technology_hits=technology_hits)

        business_flows = detect_business_flows(endpoints)
        api_graph = build_api_graph(label, [], endpoints, business_flows, fmt=self.config.graph_format)

        from .risk_engine import compute_risks

        risks = compute_risks(secrets, endpoints, [], business_flows, vulns=vulns, headers_summary={})

        return ReconResult(
            target=label,
            technologies=technologies,
            endpoints=endpoints,
            headers={},
            auth_flows=auth_flows,
            secrets=secrets,
            infra=infra,
            vulns=vulns,
            behavior=[],
            business_flows=business_flows,
            api_graph=api_graph,
            risks=risks,
            technology_hits=technology_hits,
        )

    # 3) Report rendering
    def render_report(self, result: ReconResult) -> str:
        return generate_report(result, report_format=self.config.report_format)

