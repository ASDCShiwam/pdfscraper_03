import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crawler.crawler import _expand_watermark_downloads


BASE_URL = "https://example.com/base/"


def _collect(argument: str, templates):
    return list(
        _expand_watermark_downloads(argument, set(templates), BASE_URL)
    )


def test_blank_query_parameter_is_populated():
    results = _collect("files/sample.pdf", {"download.php?download="})

    assert (
        "https://example.com/base/download.php?download=files%2Fsample.pdf" in results
    )
    assert all("show=" not in url for url in results if "download.php" in url)


def test_falls_back_to_show_parameter_when_needed():
    results = _collect("files/sample.pdf", {"download.php"})

    assert "https://example.com/base/download.php?show=files/sample.pdf" in results


def test_path_placeholder_is_replaced():
    results = _collect("files/sample.pdf", {"download.php?doc={path}"})

    assert "https://example.com/base/download.php?doc=files/sample.pdf" in results
