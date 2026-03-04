from collections import defaultdict
from typing import Any, Dict, List


FLOW_KEYWORDS = {
    "Authentication": ["auth", "login", "logout", "signin", "signup"],
    "Payment Flow": ["payment", "checkout", "cart", "order"],
    "Password Reset": ["reset-password", "password/reset", "forgot"],
    "Account Management": ["profile", "account", "user"],
    "Admin Operations": ["admin", "dashboard"],
}


def detect_business_flows(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group endpoints into business logic flows based on naming patterns.
    """
    flows: Dict[str, List[str]] = defaultdict(list)

    for ep in endpoints:
        path = ep.get("path", "").lower()
        for flow_name, keywords in FLOW_KEYWORDS.items():
            if any(k in path for k in keywords):
                flows[flow_name].append(ep["path"])

    result: List[Dict[str, Any]] = []
    for name, eps in flows.items():
        result.append({"name": name, "endpoints": sorted(set(eps))})

    return result

