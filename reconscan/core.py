"""
Core reconnaissance engine for web application and JavaScript analysis.

This module provides the main orchestration logic for scanning targets (domains or JavaScript code),
analyzing them for security vulnerabilities, exposed credentials, and reconnaissance data.

The ReconEngine supports three scanning modes:
1. Domain scanning: Crawl a website, extract JS files, and analyze them
2. JavaScript file/URL scanning: Analyze JS without crawling a domain
3. JavaScript snippet scanning: Analyze code passed directly via stdin or API

Pipeline Architecture:
- Crawler: Fetches HTML pages while respecting domain boundaries
- JS Collector: Extracts JavaScript URLs from HTML and downloads them
- JS Parser: Parses JavaScript to extract literals, identifiers, and patterns
- Classification: Identifies API endpoints, authentication flows, and sensitive data
- Detection: Scans for exposed secrets, vulnerabilities, and risky patterns
- Probing: (Optional) Validates discovered credentials with test HTTP requests
- Reporting: Generates reports in JSON, Markdown, or HTML format
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import requests
import urllib.parse

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
    """Configuration settings for the reconnaissance engine.
    
    Attributes:
        enable_behavior_probe: Whether to perform active HTTP probing of discovered endpoints (default: False)
        enable_credential_probe: Whether to validate found credentials via HTTP request (default: False - disabled for ethical reasons)
        graph_format: Output format for API relationship graphs - 'json', 'dot', or 'html' (default: 'json')
        report_format: Output format for final report - 'json', 'md', or 'html' (default: 'json')
        max_pages: Maximum number of pages to crawl when scanning a domain (default: 100)
        timeout: Socket timeout in seconds for all HTTP requests (default: 10)
    
    Note:
        Credential probing is disabled by default to ensure ethical usage. Users can opt-in
        after reviewing the report via a separate credential testing function.
    """
    enable_behavior_probe: bool = False
    enable_credential_probe: bool = False
    graph_format: str = "json"  # json | dot | html
    report_format: str = "json"  # json | md | html
    max_pages: int = 100
    timeout: int = 10


@dataclass
class ReconResult:
    """Complete reconnaissance results from a scan.
    
    Attributes:
        target: The scanned target (URL, file path, or label)
        technologies: Detected frameworks and libraries (e.g., React, Django, Spring)
        endpoints: Discovered API endpoints with extracted paths and methods
        headers: HTTP response headers from the target (security headers, server info, etc.)
        auth_flows: Detected authentication mechanisms and login/logout patterns
        secrets: Exposed credentials, API keys, tokens, and sensitive data
        infra: Infrastructure indicators (IP addresses, internal services)
        vulns: Matched vulnerability patterns based on detected technologies
        behavior: Results from active endpoint probing (if enabled)
        business_flows: Detected business logic patterns (carts, payments, admin panels)
        api_graph: Network graph of API relationships and data flow
        risks: Computed risk scores and prioritized findings
        technology_hits: Raw technology detection matches grouped by category
    """
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
    """Main orchestration class for reconnaissance scanning.
    
    Supports three scanning modes:
    - scan_domain(): Full domain reconnaissance with crawling
    - scan_js_file() / scan_js_urls(): JavaScript-only analysis
    - scan_js_snippet(): Analyze code passed as string
    
    All modes return a ReconResult with comprehensive findings.
    """
    
    def __init__(self, config: Optional[ReconConfig] = None) -> None:
        """Initialize the reconnaissance engine.
        
        Args:
            config: ReconConfig object with scanning settings. Defaults to ReconConfig() if None.
        """
        self.config = config or ReconConfig()

    def _probe_credential(self, secret: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Validate a discovered credential by making HTTP requests with it.

        Attempts to use the leaked credential against the target to determine if it's
        actually valid and functional. Tries multiple common authentication methods:
        - Authorization header (Bearer token pattern)
        - X-API-Key header (API key pattern)
        - Api-Key header (alternative API key header)
        - query parameter 'api_key' (fallback)

        Args:
            secret: Dictionary containing credential data with 'value' key
            target: Target URL to use for validation (must be accessible)

        Returns:
            Updated secret dict with testing metadata:
            - tested: Whether any test was successfully executed
            - valid: Whether credential returned HTTP status < 400
            - test_method: Header name or 'query' indicating which method worked
            - test_status: HTTP status code from the response
            - test_message: Error or success message
            - test_excerpt: First 300 chars of response body if valid
        """
        result: Dict[str, Any] = {**secret}
        result.setdefault("tested", False)
        result.setdefault("valid", False)
        result.setdefault("test_message", "")
        try:
            value = secret.get("value") or ""
            if not value:
                return result

            # Try common API authentication headers
            for hname in ("Authorization", "X-API-Key", "Api-Key"):
                if not value:
                    continue
                try:
                    resp = requests.get(target, headers={hname: value}, timeout=5)
                    result["tested"] = True
                    result["test_method"] = hname
                    result["test_status"] = resp.status_code
                    if resp.status_code < 400:
                        result["valid"] = True
                        result["test_message"] = f"received {resp.status_code}"
                        result["test_excerpt"] = resp.text[:300]
                        break
                except Exception as e:
                    # Record but continue trying other methods
                    result["test_message"] = str(e)
            # Fallback: try as query parameter if headers didn't work
            if not result.get("tested"):
                try:
                    parsed = urllib.parse.urlparse(target)
                    query = f"api_key={urllib.parse.quote(value)}"
                    newurl = urllib.parse.urlunparse(parsed._replace(query=query))
                    resp = requests.get(newurl, timeout=5)
                    result["tested"] = True
                    result["test_method"] = "query"
                    result["test_status"] = resp.status_code
                    if resp.status_code < 400:
                        result["valid"] = True
                        result["test_message"] = f"received {resp.status_code}"
                        result["test_excerpt"] = resp.text[:300]
                except Exception as e:
                    result["test_message"] = str(e)
        except Exception as e:
            result["test_message"] = str(e)
        return result

    def scan_domain(self, url: str) -> ReconResult:
        """Full reconnaissance scan of a web domain.
        
        Performs complete analysis including:
        1. Crawl domain to discover pages
        2. Extract and download JavaScript files
        3. Parse JS to extract endpoints, Auth flows, and credentials
        4. Detect technologies and vulnerabilities
        5. Optionally probe endpoints and validate credentials
        6. Map business logic flows and create API relationship graph
        7. Compute risk scores for findings
        
        Args:
            url: Target domain URL (e.g., 'https://example.com')
        
        Returns:
            ReconResult with complete findings from all analysis modules
        """
        # Step 1: Crawl the domain for HTML pages
        pages, responses = crawl_site(url, max_pages=self.config.max_pages, timeout=self.config.timeout)

        # Step 2: Extract JS file URLs from HTML and download them
        js_urls = collect_js_from_html(pages, base_url=url)
        js_sources = download_js_urls(js_urls, timeout=self.config.timeout)

        # Step 3: Parse JavaScript code to extract literals and patterns
        parsed = parse_js_sources(js_sources)

        # Step 4: Classify endpoints, infrastructure, and detect technologies
        endpoints, infra, technologies = classify_endpoints(parsed)
        technology_hits = parsed.get("technology_hits", [])
        auth_flows = detect_auth_flows(parsed, endpoints)
        
        # Step 5: Analyze HTTP headers and scan for exposed secrets
        headers = analyze_headers(responses)
        secrets = detect_secrets(parsed, responses=responses, headers=headers)
        # Credential validation is now opt-in via probe_credentials() after report generation
        
        # Step 6: Match vulnerability patterns based on detected technologies
        vulns = match_vulnerabilities(technologies, technology_hits=technology_hits)

        # Step 7: Optionally probe endpoints for behavior and response patterns
        behavior = []
        if self.config.enable_behavior_probe:
            behavior = probe_endpoints(url, endpoints, timeout=self.config.timeout)

        # Step 8: Detect business logic patterns and create API relationship graph
        business_flows = detect_business_flows(endpoints)
        api_graph = build_api_graph(url, pages, endpoints, business_flows, fmt=self.config.graph_format)

        # Step 9: Compute risk scores and prioritize findings
        from .risk_engine import compute_risks
        risks = compute_risks(secrets, endpoints, behavior, business_flows, vulns=vulns, headers_summary=headers)

        # Return complete results
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

    def scan_js_file(self, path: str) -> ReconResult:
        """Scan a local JavaScript file for endpoints and secrets.
        
        Performs static analysis without crawling or downloading files.
        Useful for analyzing downloaded or extracted JavaScript code.
        
        Args:
            path: File path to the JavaScript file to analyze
        
        Returns:
            ReconResult with findings from JS analysis only
        """
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        return self.scan_js_snippet(code, label=path)

    def scan_js_urls(self, urls: List[str]) -> ReconResult:
        """Scan multiple JavaScript URLs without crawling a domain.
        
        Downloads and analyzes JavaScript from provided URLs. Useful for
        analyzing specific JS files when domain crawling is not appropriate.
        
        Args:
            urls: List of JavaScript URLs to download and analyze
        
        Returns:
            ReconResult with findings from JS analysis only
        """
        js_sources = download_js_urls(urls, timeout=self.config.timeout)
        parsed = parse_js_sources(js_sources)
        endpoints, infra, technologies = classify_endpoints(parsed)
        technology_hits = parsed.get("technology_hits", [])
        auth_flows = detect_auth_flows(parsed, endpoints)
        
        # Analyze for secrets without HTTP headers/responses
        secrets = detect_secrets(parsed, responses=None, headers=None)
        # Credential validation is now opt-in via probe_credentials() after report generation
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
        """Scan JavaScript code provided directly as a string.
        
        Performs static analysis on supplied JavaScript code without downloading
        or crawling. Useful for analyzing code pasted via stdin or provided via API.
        
        Args:
            code: JavaScript code to analyze as string
            label: Label for the code source (default: 'stdin'). Used in reporting.
        
        Returns:
            ReconResult with findings from JS analysis only
        """
        js_sources = {label: code}
        parsed = parse_js_sources(js_sources)

        endpoints, infra, technologies = classify_endpoints(parsed)
        technology_hits = parsed.get("technology_hits", [])
        auth_flows = detect_auth_flows(parsed, endpoints)
        secrets = detect_secrets(parsed, responses=None, headers=None)
        # Credential validation is now opt-in via probe_credentials() after report generation
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
        """Generate formatted report from reconnaissance results.
        
        Renders the analysis results in the configured format (JSON, Markdown, or HTML).
        HTML reports include interactive dashboards with professional styling.
        
        Args:
            result: ReconResult object from any scan method
        
        Returns:
            Formatted report string in the configured report_format
        """
        return generate_report(result, report_format=self.config.report_format)

    def probe_credentials(self, result: ReconResult, target: str) -> ReconResult:
        """Test discovered credentials by attempting to use them against the target.
        
        This is an opt-in operation performed AFTER report generation to allow users
        to review findings before initiating any HTTP requests. Respects ethical
        guidelines by:
        - Making minimal requests per credential (max 2-3 different methods)
        - Using generic, non-destructive methods (HEAD, GET with headers)
        - Not attempting to execute commands or modify data
        - Timing out quickly (5 second limit)
        
        Args:
            result: ReconResult from a previous scan containing secrets to test
            target: Target URL to test credentials against
        
        Returns:
            Updated ReconResult with tested credentials populated with probe results
        
        Note:
            Should only be called after user explicitly consents. Makes network requests
            to the target and may trigger security alerts/logging.
        """
        tested_secrets = []
        for secret in result.secrets:
            tested_secret = self._probe_credential(secret, target)
            tested_secrets.append(tested_secret)
        
        # Update result with tested credentials
        result.secrets = tested_secrets
        return result

