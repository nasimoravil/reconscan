"""API endpoint and infrastructure detection module.

Classifies extracted endpoints by type and category (admin, auth, payment, etc.)
to help identify critical and sensitive API surfaces.

This module provides rule-based classification without machine learning.
"""

from typing import Any, Dict, List, Tuple


def _categorize_endpoint(path: str) -> str:
    """Classify endpoint path into a semantic category.
    
    Uses keyword matching on the endpoint path to determine its likely purpose
    (admin panel, authentication, payment processing, etc.).
    
    Categories:
    - admin: Administrative interface
    - auth: Authentication/login functionality
    - debug: Debug or developer tools
    - internal: Internal-only services
    - payment: Payment processing
    - password_reset: Account recovery
    - account: User profile/account management
    - generic: Generic API endpoint
    
    Args:
        path: The API endpoint path (e.g., '/api/admin/users')
    
    Returns:
        Category string for the endpoint
    """
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
    """Classify discovered API endpoints by type and category.
    
    Takes parsed JavaScript data containing raw endpoints and applies
    semantic categorization to identify endpoint purposes and risk levels.
    
    Args:
        parsed: Dictionary containing parsed JS data:
            - endpoints: List of discovered endpoint dicts
            - infra: List of infrastructure indicators
            - technologies: List of detected framework/library names
    
    Returns:
        Tuple of (endpoints, infra, technologies) where endpoints are
        enhanced with category classification
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

