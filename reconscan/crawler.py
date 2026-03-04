from collections import deque
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


def crawl_site(start_url: str, max_pages: int = 100, timeout: int = 10) -> Tuple[List[Dict], List[Dict]]:
    """
    Simple deterministic crawler:
    - Stays on the same hostname
    - Follows <a href> links
    - Captures HTML and response metadata
    """
    seen = set()
    pages: List[Dict] = []
    responses_meta: List[Dict] = []

    parsed_root = urlparse(start_url)
    queue = deque([start_url])

    with tqdm(total=max_pages, desc="Crawling", unit="page") as pbar:
        while queue and len(pages) < max_pages:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)

            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            responses_meta.append(
                {
                    "url": url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                }
            )

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            html = resp.text
            pages.append({"url": url, "html": html})
            pbar.update(1)

            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                next_url = urljoin(url, href)
                parsed = urlparse(next_url)
                if parsed.hostname != parsed_root.hostname:
                    continue
                if parsed.scheme not in ("http", "https"):
                    continue
                if next_url not in seen:
                    queue.append(next_url)

    return pages, responses_meta

