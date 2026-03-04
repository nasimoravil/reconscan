from typing import Any, Dict, List, Tuple


def _categorize_endpoint(path: str) -> str:
    lower = path.lower()
    if "admin" in lower:
        return "admin"
    if "auth" in lower or "login" in lower or "signin" in lower:
        return "auth"
    if "debug" in lower:
        return "debug"
    if "internal" in lower:
        return "internal"
    if "payment" in lower or "checkout" in lower or "cart" in lower:
        return "payment"
    if "reset" in lower and "password" in lower:
        return "password_reset"
    if "profile" in lower or "account" in lower or "user" in lower:
        return "account"
    return "generic"


def classify_endpoints(parsed: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Apply rule-based classification to endpoints discovered in JS.
    Returns (endpoints, infra, technologies).
    """
    endpoints: List[Dict[str, Any]] = []
    for ep in parsed.get("endpoints", []):
        path = ep.get("path", "")
        category = _categorize_endpoint(path)
        record = {
            "source": ep.get("source"),
            "path": path,
            "type": ep.get("type", "rest"),
            "category": category,
        }
        endpoints.append(record)

    infra = parsed.get("infra", [])
    technologies = parsed.get("technologies", [])
    return endpoints, infra, technologies

