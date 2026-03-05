"""Secret and credential detection module for reconnaissance scanning.

This module scans JavaScript code, HTTP responses, and headers for exposed
secrets including API keys, authentication tokens, database credentials, and
other sensitive data. Detection uses regex patterns from a comprehensive
credential patterns database covering 30+ credential types.

Supported Secret Types:
- Cloud credentials (AWS, Google Cloud, Azure)
- API keys (Stripe, SendGrid, GitHub, NPM)
- Authentication tokens (JWT, OAuth, Bearer tokens)
- Database credentials (MongoDB, MySQL, PostgreSQL)
- Private keys and certificates
- Internal service endpoints

The scanner performs three-layer detection:
1. JavaScript literals: Hardcoded secrets in client-side code
2. API responses: Sensitive fields in HTTP response bodies
3. HTTP headers: Security headers with potential data exposure
"""

import re
import json
import base64
from typing import Any, Dict, List, Optional
from pathlib import Path


def _load_patterns() -> Dict[str, Any]:
    """Load credential detection patterns from JSON configuration file.
    
    Reads credential_patterns.json containing regex patterns for 30+ credential
    types organized by category (cloud, payment, auth, etc.). Falls back to empty
    pattern list if file is unavailable.
    
    Returns:
        Dictionary with keys:
        - credentials: List of credential pattern definitions
        - sensitive_headers: List of HTTP header names that indicate secrets
        - sensitive_response_fields: List of field names that may contain secrets
    """
    try:
        pattern_file = Path(__file__).parent / "credential_patterns.json"
        with open(pattern_file, "r") as f:
            return json.load(f)
    except Exception:
        # Fallback to empty patterns if file is unavailable
        return {"credentials": [], "sensitive_headers": [], "sensitive_response_fields": []}


def _decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT token without signature verification.

    Extracts and decodes the payload section (middle part) of a JWT to expose
    claims. No verification is performed - this is for reconnaissance only.

    Args:
        token: JWT token string (format: header.payload.signature)

    Returns:
        Decoded JWT claims as dictionary, or None if decode fails

    Note:
        Returns None if token format is invalid or payload is malformed JSON
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Extract and decode the payload (second part)
        payload = parts[1]
        # Add base64 padding if necessary
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def _classify_severity(secret_type: str, patterns_db: Dict[str, Any]) -> str:
    """Determine severity level of a discovered secret.
    
    Looks up the secret type in the patterns database to retrieve its
    configured severity level (CRITICAL, HIGH, MEDIUM, LOW).
    
    Args:
        secret_type: Name of the secret type (e.g., 'AWS Access Key')
        patterns_db: Loaded credential patterns database
    
    Returns:
        Severity level string (default: 'MEDIUM' if not found)
    """
    for cred in patterns_db.get("credentials", []):
        if cred["name"].lower() == secret_type.lower():
            return cred.get("severity", "MEDIUM")
    return "MEDIUM"


def detect_secrets(
    parsed: Dict[str, Any],
    responses: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Scan for exposed secrets in JavaScript, HTTP responses, and headers.

    Performs three-layer detection:
    
    Layer 1 - JavaScript Literals: Searches parsed JS code for regex patterns
    matching API keys, tokens, credentials. Includes special handling for JWT
    tokens with payload decoding.
    
    Layer 2 - API Responses: Scans HTTP response bodies for sensitive field names
    that commonly contain secrets (passwords, tokens, keys, secrets).
    
    Layer 3 - HTTP Headers: Identifies security-related headers (Authorization,
    X-API-Key, Set-Cookie) that may expose sensitive data.

    Deduplication: Identical secrets found in multiple locations are reported
    only once using hash-based deduplication.

    Args:
        parsed: JavaScript parsing results dictionary containing:
            - literals: List of string literals extracted from JS code
            - Other parsed JS data (ignored for secret detection)
        responses: Optional list of HTTP response objects with status and body
        headers: Optional dict of HTTP response headers

    Returns:
        List of detected secrets, each dict containing:
        - type: Secret type name (e.g., 'AWS Access Key')
        - value: The exposed secret value
        - confidence: Confidence score (0.0-1.0) based on pattern specificity
        - severity: Risk level (CRITICAL/HIGH/MEDIUM/LOW)
        - category: Secret category (auth, payment, cloud, etc.)
        - source: Where secret was found (javascript_literal, api_response, http_header)
        - description: Human-readable description
        - jwt_claims: JWT decoded claims dict (only for JWT tokens)
        - tested: Whether credential was validated (added by credential prober)
        - valid: Whether credential tested positive (added by credential prober)
    """
    patterns_db = _load_patterns()
    findings: List[Dict[str, Any]] = []
    seen = set()  # Deduplicate by hashing credential values

    # Layer 1: Scan JavaScript code literals
    for lit in parsed.get("literals", []):
        for cred_pattern in patterns_db.get("credentials", []):
            pattern = re.compile(cred_pattern["pattern"], re.IGNORECASE)
            for m in pattern.finditer(lit):
                secret_value = m.group(0)
                secret_hash = hash(secret_value)
                
                # Skip duplicates
                if secret_hash in seen:
                    continue
                seen.add(secret_hash)
                
                # Special handling for JWT tokens: decode to extract claims
                if cred_pattern["name"] == "JWT Token":
                    jwt_claims = _decode_jwt(secret_value)
                    findings.append({
                        "type": cred_pattern["name"],
                        "value": secret_value,
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
                        "value": secret_value,
                        "confidence": 0.95,
                        "severity": cred_pattern.get("severity", "MEDIUM"),
                        "category": cred_pattern.get("category", "auth"),
                        "source": "javascript_literal",
                        "description": cred_pattern.get("description", ""),
                    })

    # Layer 2: Scan HTTP response bodies for sensitive field names
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

    # Layer 3: Scan HTTP headers for sensitive data
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

    return _deduplicate_secrets(findings)


def _deduplicate_secrets(secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate secrets from findings list.
    
    Deduplicates based on secret type and value combination to ensure only
    unique credentials are reported. Preserves the first occurrence of each
    unique secret.
    
    Args:
        secrets: List of detected secret dictionaries
    
    Returns:
        Deduplicated list of secrets with only unique items
    """
    seen = set()
    unique_secrets = []
    
    for secret in secrets:
        # Create a unique key from type and value
        secret_key = (secret.get("type", ""), secret.get("value", ""))
        
        if secret_key not in seen:
            seen.add(secret_key)
            unique_secrets.append(secret)
    
    return unique_secrets


