"""Web crawler module for domain reconnaissance.

This module provides deterministic web crawling functionality that respects domain
boundaries and extracts HTML content from discovered pages. It follows hyperlinks
found in HTML pages while staying within the target domain's scope.

Key Features:
- Respects same-domain policy (follows only links on the same hostname)
- Extracts HTTP response metadata (status, headers)
- Filters for HTML content only
- Progress tracking with configurable page limits
- Request timeout handling and error recovery
"""

from collections import deque
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


def crawl_site(start_url: str, max_pages: int = 100, timeout: int = 10) -> Tuple[List[Dict], List[Dict]]:
    """Crawl a website and extract HTML content and metadata.

    Performs a breadth-first search starting from the given URL, following all
    discovered hyperlinks while respecting domain boundaries. Collects HTTP
    response metadata and HTML content for further analysis.

    Crawling Behavior:
    - Stays on the same hostname (no subdomain following)
    - Only follows http/https links
    - Ignores non-HTML responses (images, styles, scripts served directly)
    - Skips already-visited URLs
    - Stops when max_pages limit is reached or queue is empty

    Args:
        start_url: Initial URL to crawl (e.g., 'https://example.com')
        max_pages: Maximum number of HTML pages to crawl (default: 100)
        timeout: Socket timeout in seconds for each request (default: 10)

    Returns:
        Tuple of (pages, responses_metadata):
        - pages: List of dicts with 'url' and 'html' keys containing page content
        - responses_meta: List of dicts with 'url', 'status', 'headers' from HTTP responses
    
    Note:
        Exceptions during HTTP requests or URL parsing are silently caught and
        the crawler continues with the next URL.
    """
    seen = set()
    pages: List[Dict] = []
    responses_meta: List[Dict] = []

    # Extract the root domain from start URL to enforce same-domain policy
    parsed_root = urlparse(start_url)
    queue = deque([start_url])

    # Show progress bar while crawling
    with tqdm(total=max_pages, desc="Crawling", unit="page") as pbar:
        while queue and len(pages) < max_pages:
            url = queue.popleft()
            # Skip if already visited
            if url in seen:
                continue
            seen.add(url)

            # Attempt to fetch the page
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                # Skip unavailable pages and continue crawling
                continue

            # Record response metadata
            responses_meta.append(
                {
                    "url": url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                }
            )

            # Skip non-HTML content (images, CSS, etc.)
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            # Extract and store HTML content
            html = resp.text
            pages.append({"url": url, "html": html})
            pbar.update(1)

            # Parse HTML and extract hyperlinks
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                # Convert relative URLs to absolute
                next_url = urljoin(url, href)
                parsed = urlparse(next_url)
                # Enforce same-domain policy
                if parsed.hostname != parsed_root.hostname:
                    continue
                # Only follow HTTP(S) links
                if parsed.scheme not in ("http", "https"):
                    continue
                # Queue new URLs
                if next_url not in seen:
                    queue.append(next_url)

    return pages, responses_meta

