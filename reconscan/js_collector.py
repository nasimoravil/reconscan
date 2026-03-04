from typing import Dict, List, Set
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


def collect_js_from_html(pages: List[Dict], base_url: str) -> List[str]:
    """Extract JavaScript file URLs from crawled HTML pages."""
    urls: Set[str] = set()
    for page in pages:
        html = page.get("html", "")
        url = page.get("url", base_url)
        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full = urljoin(url, src)
            urls.add(full)
    return sorted(urls)


def download_js_urls(urls: List[str], timeout: int = 10) -> Dict[str, str]:
    """Download JavaScript files, returning a mapping of URL -> source code."""
    sources: Dict[str, str] = {}
    for url in tqdm(urls, desc="Downloading JS", unit="file"):
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                continue

            ct = (resp.headers.get("Content-Type", "") or "").lower()
            looks_like_js_ct = ("javascript" in ct) or ("ecmascript" in ct)
            looks_like_js_url = url.lower().split("?", 1)[0].endswith(".js")
            body = resp.text or ""
            looks_like_js_body = any(
                token in body[:500]
                for token in ("function", "const ", "let ", "var ", "=>", "import ", "export ")
            )

            if looks_like_js_ct or looks_like_js_url or looks_like_js_body:
                sources[url] = body
        except requests.RequestException:
            continue
    return sources

