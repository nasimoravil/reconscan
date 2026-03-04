import re
import json
import base64
from typing import Any, Dict, List, Optional
from pathlib import Path


def _load_patterns() -> Dict[str, Any]:
    """Load credential patterns from JSON file."""
    try:
        pattern_file = Path(__file__).parent / "credential_patterns.json"
        with open(pattern_file, "r") as f:
            return json.load(f)
    except Exception:
        # Fallback patterns if JSON unavailable
        return {"credentials": [], "sensitive_headers": [], "sensitive_response_fields": []}


def _decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Attempt to decode JWT and extract claims without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def _classify_severity(secret_type: str, patterns_db: Dict[str, Any]) -> str:
    """Classify severity based on secret type."""
    for cred in patterns_db.get("credentials", []):
        if cred["name"].lower() == secret_type.lower():
            return cred.get("severity", "MEDIUM")
    return "MEDIUM"


def detect_secrets(
    parsed: Dict[str, Any],
    responses: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Scan JS literals, API responses, and headers for exposed secrets.
    
    Args:
        parsed: JS parsing results with literals
        responses: Optional HTTP response data
        headers: Optional HTTP headers
    
    Returns:
        List of detected secrets with context
    """
    patterns_db = _load_patterns()
    findings: List[Dict[str, Any]] = []
    seen = set()  # Deduplicate by hashing credential values

    # 1. Scan JS literals
    for lit in parsed.get("literals", []):
        for cred_pattern in patterns_db.get("credentials", []):
            pattern = re.compile(cred_pattern["pattern"], re.IGNORECASE)
            for m in pattern.finditer(lit):
                secret_value = m.group(0)
                secret_hash = hash(secret_value)
                
                if secret_hash in seen:
                    continue
                seen.add(secret_hash)
                
                # Check if it's a JWT for special handling
                if cred_pattern["name"] == "JWT Token":
                    jwt_claims = _decode_jwt(secret_value)
                    findings.append({
                        "type": cred_pattern["name"],
                        "value": secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                        "confidence": 0.95,
                        "severity": cred_pattern.get("severity", "MEDIUM"),
                        "category": cred_pattern.get("category", "auth"),
                        "source": "javascript_literal",
                        "description": cred_pattern.get("description", ""),
                        "jwt_claims": jwt_claims if jwt_claims else None,
                    })
                else:
                    findings.append({
                        "type": cred_pattern["name"],
                        "value": secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                        "confidence": 0.95,
                        "severity": cred_pattern.get("severity", "MEDIUM"),
                        "category": cred_pattern.get("category", "auth"),
                        "source": "javascript_literal",
                        "description": cred_pattern.get("description", ""),
                    })

    # 2. Scan API responses
    if responses:
        sensitive_fields = patterns_db.get("sensitive_response_fields", [])
        for resp in responses:
            if isinstance(resp, dict):
                for field in sensitive_fields:
                    if field.lower() in str(resp).lower():
                        findings.append({
                            "type": "Sensitive Data in Response",
                            "value": f"Field '{field}' detected",
                            "confidence": 0.70,
                            "severity": "HIGH",
                            "category": "response",
                            "source": "api_response",
                            "description": f"Response contains potentially sensitive field: {field}",
                        })

    # 3. Scan headers
    if headers:
        sensitive_headers = patterns_db.get("sensitive_headers", [])
        for header_name in sensitive_headers:
            if header_name in headers or header_name.lower() in str(headers).lower():
                findings.append({
                    "type": "Sensitive Header",
                    "value": header_name,
                    "confidence": 0.85,
                    "severity": "MEDIUM",
                    "category": "header",
                    "source": "http_header",
                    "description": f"Sensitive header '{header_name}' found",
                })

    return findings


