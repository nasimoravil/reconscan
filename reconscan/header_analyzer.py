from typing import Dict, List, Any


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def analyze_headers(responses_meta: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarise HTTP security headers and CORS behavior from crawled responses.
    """
    if not responses_meta:
        return {}

    summary: Dict[str, Any] = {"samples": [], "header_issues": []}

    for resp in responses_meta[:10]:
        headers = resp.get("headers", {})
        entry = {
            "url": resp.get("url"),
            "status": resp.get("status"),
            "headers": headers,
        }
        summary["samples"].append(entry)

        # Missing important security headers
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if missing:
            summary["header_issues"].append(
                {
                    "url": resp.get("url"),
                    "missing": missing,
                }
            )

        # CORS wildcard
        acao = headers.get("Access-Control-Allow-Origin")
        if acao == "*":
            summary["header_issues"].append(
                {
                    "url": resp.get("url"),
                    "issue": "Wildcard CORS",
                    "header": "Access-Control-Allow-Origin: *",
                }
            )

    return summary

