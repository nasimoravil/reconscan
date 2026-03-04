import re
from typing import Any, Dict, List


SECRET_PATTERNS = {
    "Google API key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Stripe Live Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+"),
}


def detect_secrets(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan collected literals for exposed secrets using regex."""
    findings: List[Dict[str, Any]] = []
    for lit in parsed.get("literals", []):
        for name, pattern in SECRET_PATTERNS.items():
            for m in pattern.finditer(lit):
                findings.append(
                    {
                        "type": name,
                        "value": m.group(0),
                    }
                )
    return findings

