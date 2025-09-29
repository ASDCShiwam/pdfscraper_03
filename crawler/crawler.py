import hashlib
import logging
import os
import re
import time
from collections import deque
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set
from urllib.parse import ParseResult, urljoin, urldefrag, urlparse, unquote

import bs4
import requests
from bs4 import BeautifulSoup

# Custom headers to mimic a real browser request
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    )
}

VERIFY_SSL = os.getenv("CRAWLER_VERIFY_SSL", "true").lower() not in {
    "0",
    "false",
    "no",
}

_SESSION = requests.Session()
_SESSION.headers.update(HEADERS)
_SESSION.verify = VERIFY_SSL

PDF_PATTERN = re.compile(r"[^'\"()<>\\\s]+\.pdf(?:[?#][^'\"()<>\\\s]*)?", re.IGNORECASE)

logger = logging.getLogger(__name__)


def crawl_and_download(
    start_url: str,
    download_folder: Path,
    retries: int = 3,
    delay: int = 5,
    *,
    allowed_hosts: Optional[Iterable[str]] = None,
    max_pages: Optional[int] = None,
    max_pdfs: Optional[int] = None,
) -> List[Dict[str, str]]:
    """Crawl a website starting from ``start_url`` and download every PDF that is found.

    Parameters
    ----------
    start_url:
        The first page that will be crawled.
    download_folder:
        The directory where downloaded PDFs should be stored.
    retries:
        Number of attempts to make when a request fails due to timeout or transient
        issues.
    delay:
        Number of seconds to wait between retries.

    allowed_hosts:
        Optional iterable of hostnames that are allowed during the crawl. When
        provided, only links that resolve to these hosts will be followed. This
        is useful for intranet environments to avoid accidentally crawling the
        public internet when offline mirrors link externally.

    max_pages:
        Optional safety limit to stop crawling after visiting this many pages.
        ``None`` disables the limit.
    max_pdfs:
        Optional safety limit to stop downloading once this many PDFs were
        successfully saved. ``None`` disables the limit.

    Returns
    -------
    list of dict
        Metadata for every PDF that was downloaded. Each item contains ``url``,
        ``path`` (local path on disk), ``filename`` and ``downloaded_at``. The page
        where the file was discovered is stored under ``source_page``.
    """

    download_folder = Path(download_folder)
    download_folder.mkdir(parents=True, exist_ok=True)

    visited: Set[str] = set()
    queue: deque[str] = deque([start_url])
    downloaded: List[Dict[str, str]] = []
    downloaded_urls: Set[str] = set()
    allowed: Optional[Set[str]] = None
    if allowed_hosts:
        allowed = set()
        for host in allowed_hosts:
            lowered = host.lower()
            allowed.add(lowered)
            if ":" in lowered:
                allowed.add(lowered.split(":", 1)[0])

    while queue:
        if max_pages is not None and len(visited) >= max_pages:
            logger.info("Reached maximum page limit of %s", max_pages)
            break

        current_url = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)

        response = _request_with_retries(current_url, retries=retries, delay=delay)
        if response is None:
            continue

        if not _is_html_response(response):
            logger.debug("Skipping non-HTML content at %s", current_url)
            continue

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except (bs4.FeatureNotFound, bs4.builder.ParserRejectedMarkup, AssertionError) as exc:
            logger.warning("Skipping %s: unable to parse HTML (%s)", current_url, exc)
            continue

        pdf_links = _extract_pdf_urls(soup, current_url)
        for pdf_url in pdf_links:
            parsed_pdf = urlparse(pdf_url)
            if allowed and not _is_allowed_host(parsed_pdf, allowed):
                continue

            if pdf_url in downloaded_urls:
                continue

            pdf_info = download_pdf(pdf_url, download_folder)
            if pdf_info:
                pdf_info["source_page"] = current_url
                downloaded.append(pdf_info)
                downloaded_urls.add(pdf_url)

                if max_pdfs is not None and len(downloaded) >= max_pdfs:
                    logger.info("Reached maximum PDF limit of %s", max_pdfs)
                    return downloaded

        for link in soup.select("a[href]"):
            href = link.get("href")
            if not href:
                continue

            href, _fragment = urldefrag(href)
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)

            if parsed.scheme not in {"http", "https"}:
                continue

            if allowed and not _is_allowed_host(parsed, allowed):
                continue

            if parsed.path.lower().endswith(".pdf"):
                continue

            if full_url not in visited:
                queue.append(full_url)

    return downloaded


def _is_allowed_host(parsed: ParseResult, allowed: Set[str]) -> bool:
    netloc = parsed.netloc.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    return netloc in allowed or hostname in allowed


def _iter_attribute_strings(value: object) -> Iterator[str]:
    if value is None:
        return

    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_attribute_strings(item)
        return

    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_attribute_strings(item)
        return

    yield str(value)


def _normalize_pdf_candidate(candidate: str, base_url: str) -> Optional[str]:
    candidate = candidate.strip().strip("'\"")
    if not candidate or candidate.lower().startswith("javascript:"):
        return None

    if candidate.startswith("//"):
        base_parsed = urlparse(base_url)
        candidate = f"{base_parsed.scheme}:{candidate}"

    normalized = urljoin(base_url, candidate)
    parsed = urlparse(normalized)

    if parsed.scheme not in {"http", "https"}:
        return None

    if not parsed.path.lower().endswith(".pdf"):
        return None

    parsed = parsed._replace(fragment="")
    return parsed.geturl()


def _extract_pdf_urls(soup: BeautifulSoup, base_url: str) -> List[str]:
    discovered: Dict[str, None] = {}

    for element in soup.find_all(True):
        for attr_value in element.attrs.values():
            for text_value in _iter_attribute_strings(attr_value):
                for match in PDF_PATTERN.finditer(text_value):
                    normalized = _normalize_pdf_candidate(match.group(0), base_url)
                    if normalized:
                        discovered.setdefault(normalized, None)

    for script in soup.find_all("script"):
        script_text = script.string or script.get_text() or ""
        for match in PDF_PATTERN.finditer(script_text):
            normalized = _normalize_pdf_candidate(match.group(0), base_url)
            if normalized:
                discovered.setdefault(normalized, None)

    return list(discovered.keys())


def _get_with_ssl_fallback(
    url: str,
    *,
    timeout: int,
    stream: bool = False,
) -> Optional[requests.Response]:
    """Perform a GET request with an optional SSL verification fallback."""

    try:
        return _SESSION.get(url, timeout=timeout, stream=stream)
    except requests.exceptions.Timeout:
        logger.warning("Timeout while requesting %s", url)
        return None
    except requests.exceptions.SSLError as exc:  # pragma: no cover - network dependent
        if not VERIFY_SSL:
            logger.error("SSL error for %s despite verification disabled: %s", url, exc)
            return None

        logger.warning(
            "SSL verification failed for %s (%s). Retrying without certificate checks.",
            url,
            exc,
        )

        try:
            return _SESSION.get(url, timeout=timeout, stream=stream, verify=False)
        except requests.exceptions.RequestException as insecure_exc:
            logger.error(
                "Fallback request without SSL verification failed for %s: %s",
                url,
                insecure_exc,
            )
            return None
    except requests.exceptions.RequestException as exc:
        logger.error("Request error for %s: %s", url, exc)
        return None


def _request_with_retries(
    url: str,
    retries: int = 3,
    delay: int = 5,
) -> Optional[requests.Response]:
    """Fetch ``url`` while retrying transient failures."""

    attempt = 0
    while attempt < retries:
        response = _get_with_ssl_fallback(url, timeout=15)
        if response is None:
            attempt += 1
            if attempt >= retries:
                break
            logger.warning(
                "Retrying %s after failure (attempt %s/%s)", url, attempt + 1, retries
            )
            time.sleep(delay)
            continue

        if response.status_code == 200:
            logger.info("Successfully accessed %s", url)
            return response

        if response.status_code in (403, 404):
            logger.warning("%s returned status %s", url, response.status_code)
            return None

        logger.warning(
            "Failed to access %s, status code %s", url, response.status_code
        )
        return None

    logger.error("Giving up on %s after %s attempts", url, retries)
    return None



def _is_html_response(response: requests.Response) -> bool:
    """Return ``True`` when ``response`` looks like an HTML document."""

    content_type = response.headers.get("Content-Type", "").lower()
    if "html" in content_type or "xml" in content_type:
        return True

    if content_type.startswith("text/"):
        return True

    return False



def _unique_target_path(folder: Path, pdf_name: str, url: str) -> Path:
    """Return a unique file path for ``pdf_name`` within ``folder``."""

    candidate = folder / pdf_name
    if not candidate.exists():
        return candidate

    stem, suffix = os.path.splitext(pdf_name)
    safe_stem = stem or "downloaded"
    # Use a deterministic suffix derived from the URL to avoid clobbering
    # similarly named files discovered on different pages.
    hashed = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    candidate = folder / f"{safe_stem}_{hashed}{suffix or '.pdf'}"
    return candidate


def _filename_from_content_disposition(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None

    match = re.search(r"filename\*=([^;]+)", header_value, flags=re.IGNORECASE)
    if match:
        value = match.group(1).strip().strip("\"')")
        if value.lower().startswith("utf-8''"):
            value = value[7:]
        value = unquote(value)
        return os.path.basename(value) or None

    match = re.search(r"filename=([^;]+)", header_value, flags=re.IGNORECASE)
    if match:
        value = match.group(1).strip().strip("\"')")
        value = unquote(value)
        return os.path.basename(value) or None

    return None


def _looks_like_pdf(first_chunk: bytes, headers: requests.structures.CaseInsensitiveDict) -> bool:
    content_type = headers.get("Content-Type", "").lower()
    if "pdf" in content_type:
        return True

    if first_chunk.lstrip().startswith(b"%PDF"):
        return True

    return False


def download_pdf(url: str, folder: Path) -> Optional[Dict[str, str]]:
    """Download a PDF file and return metadata about it."""

    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)

    parsed = urlparse(url)
    fallback_name = os.path.basename(parsed.path) or "downloaded.pdf"

    response = _get_with_ssl_fallback(url, timeout=30, stream=True)
    if response is None:
        logger.error("Failed to download %s due to request issues", url)
        return None

    with closing(response):
        try:
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            logger.error("Failed to download %s: %s", url, exc)
            return None

        chunk_iterator = response.iter_content(chunk_size=8192)
        first_chunk = b""
        for chunk in chunk_iterator:
            if chunk:
                first_chunk = chunk
                break

        if not first_chunk:
            logger.error("No content returned for %s", url)
            return None

        if not _looks_like_pdf(first_chunk, response.headers):
            logger.warning(
                "Content from %s does not appear to be a PDF (Content-Type: %s)",
                url,
                response.headers.get("Content-Type", "unknown"),
            )
            return None

        header_filename = _filename_from_content_disposition(
            response.headers.get("Content-Disposition")
        )
        pdf_name = header_filename or fallback_name
        if not pdf_name.lower().endswith(".pdf"):
            pdf_name = f"{pdf_name}.pdf"

        target_path = _unique_target_path(folder, pdf_name, url)
        if target_path.exists():
            logger.info("%s already exists, skipping download", target_path)
            return {
                "url": url,
                "path": str(target_path),
                "filename": target_path.name,
                "downloaded_at": datetime.utcfromtimestamp(
                    target_path.stat().st_mtime
                ).isoformat()
                + "Z",
            }

        with open(target_path, "wb") as file_pointer:
            file_pointer.write(first_chunk)
            for chunk in chunk_iterator:
                if chunk:
                    file_pointer.write(chunk)

    logger.info("Downloaded %s", pdf_name)
    return {
        "url": url,
        "path": str(target_path),
        "filename": target_path.name,
        "downloaded_at": datetime.utcnow().isoformat() + "Z",
    }
