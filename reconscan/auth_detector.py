import re
from typing import Any, Dict, List


AUTH_HEADER_MARKERS = [
    "authorization: bearer",
    "authorization: jwt",
    "oauth",
]

SESSION_MARKERS = [
    "sessionid",
    "asp.net_sessionid",
]

CSRF_MARKERS = [
    "__requestverificationtoken",
    "csrf-token",
]


def detect_auth_flows(parsed: Dict[str, Any], endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect authentication-related flows based on endpoint categories and literal markers.
    """
    literals = [s.lower() for s in parsed.get("literals", [])]

    indicators: List[str] = []
    for marker in AUTH_HEADER_MARKERS + SESSION_MARKERS + CSRF_MARKERS:
        if any(marker in lit for lit in literals):
            indicators.append(marker)

    auth_endpoints = [ep for ep in endpoints if ep.get("category") == "auth"]

    flows: List[Dict[str, Any]] = []
    if auth_endpoints:
        # Basic JWT vs session heuristic
        auth_type = "unknown"
        if any("authorization: bearer" in ind for ind in indicators):
            auth_type = "jwt"
        elif any(m in indicators for m in SESSION_MARKERS):
            auth_type = "session"

        flows.append(
            {
                "name": "User Authentication",
                "type": auth_type,
                "endpoints": [ep["path"] for ep in auth_endpoints],
                "indicators": indicators,
            }
        )

    # Also look for explicit /auth/login even if not categorized
    for ep in endpoints:
        if re.search(r"/auth/login", ep.get("path", ""), re.I) and not any(
            "/auth/login" in e for f in flows for e in f.get("endpoints", [])
        ):
            flows.append(
                {
                    "name": "User Authentication",
                    "type": "login-endpoint",
                    "endpoints": [ep["path"]],
                    "indicators": indicators,
                }
            )

    return flows

