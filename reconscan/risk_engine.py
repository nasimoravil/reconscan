from typing import Any, Dict, List, Optional


def compute_risks(
    secrets: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]],
    behavior: List[Dict[str, Any]],
    business_flows: List[Dict[str, Any]],
    vulns: Optional[List[Dict[str, Any]]] = None,
    headers_summary: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Assign severity scores to notable findings.
    Severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL.
    """
    risks: List[Dict[str, Any]] = []
    vulns = vulns or []
    headers_summary = headers_summary or {}

    # CRITICAL: any exposed secret
    for s in secrets:
        risks.append(
            {
                "severity": "CRITICAL",
                "title": f"Exposed {s.get('type')}",
                "details": {
                    "value": s.get("value"),
                },
            }
        )

    # HIGH/MEDIUM: known vulnerable libraries
    for v in vulns:
        sev = (v.get("severity") or "MEDIUM").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "MEDIUM"
        risks.append(
            {
                "severity": sev,
                "title": f"Vulnerable dependency match: {v.get('technology_instance', v.get('technology'))}",
                "details": {
                    "cve": v.get("cve"),
                    "description": v.get("description"),
                    "cisa_kev": v.get("cisa_kev"),
                    "sources": v.get("sources", []),
                },
            }
        )

    # HIGH: public admin endpoints (HTTP 200)
    behavior_index = {b.get("path"): b for b in behavior}
    for ep in endpoints:
        if ep.get("category") == "admin":
            beh = behavior_index.get(ep.get("path"))
            if beh and beh.get("get_status") == 200 and not beh.get("auth_required", False):
                risks.append(
                    {
                        "severity": "HIGH",
                        "title": "Public admin endpoint",
                        "details": {
                            "path": ep.get("path"),
                            "url": beh.get("url"),
                        },
                    }
                )

    # MEDIUM: debug endpoints reachable
    for ep in endpoints:
        if ep.get("category") == "debug":
            beh = behavior_index.get(ep.get("path"))
            if beh and beh.get("get_status") == 200:
                risks.append(
                    {
                        "severity": "MEDIUM",
                        "title": "Debug endpoint exposed",
                        "details": {
                            "path": ep.get("path"),
                            "url": beh.get("url"),
                        },
                    }
                )

    # MEDIUM/LOW: missing security headers and wildcard CORS
    for issue in headers_summary.get("header_issues", []):
        if issue.get("issue") == "Wildcard CORS":
            risks.append(
                {
                    "severity": "MEDIUM",
                    "title": "Wildcard CORS policy detected",
                    "details": issue,
                }
            )
        elif issue.get("missing"):
            risks.append(
                {
                    "severity": "LOW",
                    "title": "Missing recommended security headers",
                    "details": issue,
                }
            )

    # INFO: presence of high-value business flows
    for flow in business_flows:
        risks.append(
            {
                "severity": "INFO",
                "title": f"Business Flow: {flow.get('name')}",
                "details": {
                    "endpoints": flow.get("endpoints"),
                },
            }
        )

    return risks

