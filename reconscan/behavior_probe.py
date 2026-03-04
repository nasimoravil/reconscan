from typing import Any, Dict, List
from urllib.parse import urljoin

import requests


def probe_endpoints(base_url: str, endpoints: List[Dict[str, Any]], timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Safely probe discovered endpoints with HEAD and GET (no parameters).
    Records status codes, redirect behavior, and basic auth/ratelimit hints.
    """
    results: List[Dict[str, Any]] = []
    for ep in endpoints:
        path = ep.get("path")
        if not path:
            continue
        url = path
        if url.startswith("/"):
            url = urljoin(base_url, url)

        info: Dict[str, Any] = {
            "path": path,
            "url": url,
            "category": ep.get("category"),
            "head_status": None,
            "get_status": None,
            "redirects": [],
            "auth_required": False,
            "rate_limit_headers": {},
        }

        try:
            head_resp = requests.head(url, allow_redirects=True, timeout=timeout)
            info["head_status"] = head_resp.status_code
            info["redirects"] = [r.url for r in head_resp.history]
            if head_resp.status_code in (401, 403) or "www-authenticate" in (
                {k.lower(): v for k, v in head_resp.headers.items()}
            ):
                info["auth_required"] = True

            rl_headers = {
                k: v
                for k, v in head_resp.headers.items()
                if k.lower().startswith("x-ratelimit") or k.lower() == "rate-limit"
            }
            if rl_headers:
                info["rate_limit_headers"] = rl_headers
        except requests.RequestException:
            pass

        try:
            get_resp = requests.get(url, allow_redirects=True, timeout=timeout)
            info["get_status"] = get_resp.status_code
            # If GET gives 401/403 but HEAD did not, still flag auth
            if get_resp.status_code in (401, 403):
                info["auth_required"] = True
        except requests.RequestException:
            pass

        # Simple risk hint for debug endpoints exposed
        if info["get_status"] == 200 and ep.get("category") == "debug":
            info["risk"] = "debug endpoint exposed publicly"

        results.append(info)

    return results

