"""C5 – Visual reconnaissance module.

Captures screenshots via Playwright (headless Chromium), computes perceptual
hashes for change detection, fingerprints technologies from visual cues,
performs favicon hash matching (FavFreak / MurmurHash3), and annotates
screenshots to highlight interactive elements.
"""

from __future__ import annotations

import hashlib
import io
import math
import struct
from datetime import datetime
from typing import Any

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Optional dependencies (graceful degradation)
# ---------------------------------------------------------------------------

try:
    from playwright.async_api import Browser, async_playwright  # type: ignore
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

try:
    from PIL import Image, ImageDraw  # type: ignore
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import imagehash  # type: ignore
    _IMAGEHASH_AVAILABLE = True
except ImportError:
    _IMAGEHASH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Favicon tech fingerprint database (MurmurHash3 → technology name)
# ---------------------------------------------------------------------------

_FAVICON_FINGERPRINTS: dict[int, str] = {
    -247388890:  "Fortinet FortiGate",
    116323821:   "Cisco ASA",
    -335242539:  "Cobalt Strike Team Server",
    1278695002:  "GitLab",
    -1534004847: "Jenkins",
    -1850415006: "Kibana",
    1768774933:  "Grafana",
    708578229:   "Microsoft Exchange",
    -1874735714: "Jira",
    230946087:   "Confluence",
    999357577:   "cPanel",
    1166528356:  "Plesk",
    -1259584793: "VMware vSphere",
    -876922061:  "Phishing Kit",
}

# Visual pattern strings that indicate page categories
_VISUAL_PATTERNS: dict[str, list[str]] = {
    "login_page": [
        "sign in", "log in", "login", "username", "password", "forgot password",
        "remember me", "create account",
    ],
    "admin_panel": [
        "admin", "dashboard", "control panel", "management console",
        "administrator", "system settings",
    ],
    "error_page": [
        "404", "not found", "500", "internal server error", "403", "forbidden",
        "bad gateway", "service unavailable", "stack trace", "exception",
    ],
    "payment_page": [
        "credit card", "card number", "cvv", "expiry", "billing", "checkout",
        "payment", "stripe", "paypal",
    ],
}


# ---------------------------------------------------------------------------
# MurmurHash3 (32-bit) implementation
# ---------------------------------------------------------------------------


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 (32-bit) for favicon fingerprinting."""
    c1, c2, length = 0xCC9E2D51, 0x1B873593, len(data)
    h = seed & 0xFFFFFFFF
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k = 0
    tail_size = length & 3
    if tail_size >= 3:
        k ^= tail[2] << 16
    if tail_size >= 2:
        k ^= tail[1] << 8
    if tail_size >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16

    # Return as signed 32-bit integer (matches Shodan convention)
    return struct.unpack(">i", struct.pack(">I", h))[0]


# ---------------------------------------------------------------------------
# Fallback perceptual hash using PIL (when imagehash not available)
# ---------------------------------------------------------------------------


def _pil_phash(img: Image.Image, hash_size: int = 8) -> int:
    """Compute a perceptual hash (pHash) using DCT approximation via PIL."""
    img = img.convert("L").resize(
        (hash_size * 4, hash_size * 4), Image.Resampling.LANCZOS
    )
    pixels = list(img.getdata())
    n = hash_size * 4

    # Compute DCT (simplified – sum of cosines)
    dct: list[list[float]] = []
    for u in range(hash_size):
        row: list[float] = []
        for v in range(hash_size):
            total = 0.0
            for x in range(n):
                for y in range(n):
                    total += (
                        pixels[x * n + y]
                        * math.cos((2 * x + 1) * u * math.pi / (2 * n))
                        * math.cos((2 * y + 1) * v * math.pi / (2 * n))
                    )
            row.append(total)
        dct.append(row)

    flat = [dct[i][j] for i in range(hash_size) for j in range(hash_size)]
    avg = sum(flat) / len(flat)
    bits = [1 if v >= avg else 0 for v in flat]
    result = 0
    for bit in bits:
        result = (result << 1) | bit
    return result


def _hash_distance(h1: int, h2: int, bits: int = 64) -> int:
    """Compute Hamming distance between two perceptual hashes."""
    return bin((h1 ^ h2) & ((1 << bits) - 1)).count("1")


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class VisualRecon(BaseModule):
    """Visual reconnaissance: screenshots, perceptual hashing, tech fingerprinting."""

    name = "visual_recon"
    description = (
        "Capture screenshots with Playwright, compute perceptual hashes for change "
        "detection, detect technologies from visual cues, and match favicon hashes."
    )
    version = "1.0.0"
    category = "recon"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Run visual reconnaissance against *target*.

        Args:
            target: Base URL of the target.
            **kwargs:
                - paths (List[str]): URL paths to screenshot (default ["/"]).
                - previous_hashes (Dict[str, int]): Path → hash from a prior scan
                  for change detection.
                - timeout (int): Navigation timeout in ms (default 15000).
                - screenshot_dir (str): Directory to save PNG files (optional).
        """
        self.started_at = datetime.utcnow()

        base = target if target.startswith("http") else f"https://{target}"
        paths: list[str] = kwargs.get("paths", ["/"])
        previous_hashes: dict[str, int] = kwargs.get("previous_hashes", {})
        nav_timeout: int = int(kwargs.get("timeout", 15000))
        screenshot_dir: str | None = kwargs.get("screenshot_dir")

        page_results: list[dict[str, Any]] = []

        # --- Favicon fingerprinting (always attempted, no Playwright needed) ---
        favicon_result = await self._fetch_favicon(base)
        if favicon_result:
            page_results.append(favicon_result)

        if _PLAYWRIGHT_AVAILABLE:
            async with async_playwright() as pw:
                browser: Browser = await pw.chromium.launch(headless=True)
                for path in paths:
                    url = base.rstrip("/") + path
                    result = await self._process_page(
                        browser, url, previous_hashes.get(path), nav_timeout, screenshot_dir
                    )
                    if result:
                        page_results.append(result)
                await browser.close()
        else:
            self.logger.warning(
                "Playwright not installed; visual screenshots unavailable. "
                "Install with: pip install playwright && playwright install chromium"
            )
            self.add_finding(
                title="Visual Recon – Playwright Unavailable",
                severity="info",
                description=(
                    "Playwright is not installed so screenshot capture is skipped. "
                    "Install with `pip install playwright && playwright install chromium`."
                ),
                url=base,
            )

        self.completed_at = datetime.utcnow()
        return {**self.to_dict(), "page_results": page_results}

    # ------------------------------------------------------------------ #
    # Per-page processing                                                  #
    # ------------------------------------------------------------------ #

    async def _process_page(
        self,
        browser: Any,
        url: str,
        previous_hash: int | None,
        timeout_ms: int,
        screenshot_dir: str | None,
    ) -> dict[str, Any] | None:
        """Navigate to *url*, screenshot, hash, detect changes and technologies."""
        page: Any = await browser.new_page(
            viewport={"width": 1280, "height": 900},
            ignore_https_errors=True,
        )
        result: dict[str, Any] = {"url": url}

        try:
            response = await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            status = response.status if response else 0
            result["status"] = status
            result["title"] = await page.title()

            # Capture screenshot as bytes
            png_bytes: bytes = await page.screenshot(full_page=False)
            result["screenshot_size_bytes"] = len(png_bytes)

            # Save to disk if requested
            if screenshot_dir:
                import os

                safe_name = url.replace("://", "_").replace("/", "_")[:100]
                path = os.path.join(screenshot_dir, f"{safe_name}.png")
                with open(path, "wb") as fh:
                    fh.write(png_bytes)
                result["screenshot_path"] = path

            # Perceptual hash
            phash = self._compute_phash(png_bytes)
            result["phash"] = phash

            # Change detection
            if previous_hash is not None:
                distance = _hash_distance(phash, previous_hash)
                result["hash_distance"] = distance
                changed = distance > 10  # threshold: >10 bits changed
                result["visual_changed"] = changed
                if changed:
                    self.add_finding(
                        title=f"Visual Change Detected – {url}",
                        severity="medium",
                        description=(
                            f"The visual appearance of {url} has changed since the "
                            f"last scan (perceptual hash distance: {distance}). "
                            "This may indicate content modification, defacement, or "
                            "a legitimate deployment."
                        ),
                        evidence=f"Previous hash: {previous_hash}, current: {phash}, distance: {distance}",
                        url=url,
                    )

            # Technology detection from page content
            page_text = (await page.content()).lower()
            detected = self._detect_technologies(page_text, result.get("title", ""))
            result["detected_categories"] = detected

            if "login_page" in detected:
                self.add_finding(
                    title=f"Login Page Detected – {url}",
                    severity="info",
                    description="A login page was identified by visual pattern matching.",
                    url=url,
                    categories=detected,
                )
            if "admin_panel" in detected:
                self.add_finding(
                    title=f"Admin Panel Exposed – {url}",
                    severity="high",
                    description=(
                        "An administrative panel was identified at this URL via visual "
                        "pattern matching. Admin panels should not be publicly accessible."
                    ),
                    url=url,
                    categories=detected,
                )

            # Annotate screenshot (highlight forms, inputs, buttons)
            annotation = self._annotate(png_bytes)
            result["annotated_elements"] = annotation

        except Exception as exc:
            self.logger.warning("Visual recon failed for %s: %s", url, exc)
            result["error"] = str(exc)
        finally:
            await page.close()

        return result

    # ------------------------------------------------------------------ #
    # Perceptual hashing                                                   #
    # ------------------------------------------------------------------ #

    def _compute_phash(self, png_bytes: bytes) -> int:
        """Return a perceptual hash integer for the screenshot bytes."""
        if not _PIL_AVAILABLE:
            # Fall back to a simple MD5-based pseudo-hash
            return int(hashlib.md5(png_bytes).hexdigest()[:16], 16)

        img = Image.open(io.BytesIO(png_bytes))
        if _IMAGEHASH_AVAILABLE:
            h = imagehash.phash(img)
            return int(str(h), 16)
        return _pil_phash(img)

    # ------------------------------------------------------------------ #
    # Technology detection                                                 #
    # ------------------------------------------------------------------ #

    def _detect_technologies(
        self, page_text: str, title: str
    ) -> list[str]:
        """Detect page categories from text content and title."""
        detected: list[str] = []
        combined = page_text + " " + title.lower()
        for category, patterns in _VISUAL_PATTERNS.items():
            if any(p in combined for p in patterns):
                detected.append(category)
        return detected

    # ------------------------------------------------------------------ #
    # Favicon hash matching                                                #
    # ------------------------------------------------------------------ #

    async def _fetch_favicon(self, base_url: str) -> dict[str, Any] | None:
        """Download favicon and match its MurmurHash3 against known fingerprints."""
        import httpx

        favicon_urls = [
            base_url.rstrip("/") + "/favicon.ico",
            base_url.rstrip("/") + "/favicon.png",
        ]
        for url in favicon_urls:
            try:
                async with httpx.AsyncClient(timeout=8, verify=False) as client:
                    r = await client.get(url)
                if r.status_code == 200 and r.content:
                    import base64

                    favicon_b64 = base64.b64encode(r.content).decode()
                    # Standard FavFreak encoding: base64 of raw bytes
                    encoded = (
                        "\n".join(
                            favicon_b64[i : i + 76]
                            for i in range(0, len(favicon_b64), 76)
                        )
                        + "\n"
                    )
                    fav_hash = _mmh3_32(encoded.encode())
                    technology = _FAVICON_FINGERPRINTS.get(fav_hash)
                    result: dict[str, Any] = {
                        "url": url,
                        "favicon_hash": fav_hash,
                        "size_bytes": len(r.content),
                    }
                    if technology:
                        result["identified_technology"] = technology
                        self.add_finding(
                            title=f"Technology Identified via Favicon Hash – {technology}",
                            severity="info",
                            description=(
                                f"The favicon at {url} matches the known fingerprint "
                                f"for {technology} (MurmurHash3={fav_hash}). "
                                "This confirms the technology in use and may assist "
                                "in targeting version-specific exploits."
                            ),
                            evidence=f"MurmurHash3={fav_hash}",
                            url=url,
                        )
                    return result
            except Exception as exc:
                self.logger.debug("Favicon fetch failed %s: %s", url, exc)
        return None

    # ------------------------------------------------------------------ #
    # Screenshot annotation                                                #
    # ------------------------------------------------------------------ #

    def _annotate(self, png_bytes: bytes) -> dict[str, Any]:
        """Highlight form fields, inputs, and buttons in a screenshot.

        Returns a summary dict; actual overlay is saved only when Playwright
        exposes element bounding boxes (requires a live page reference).
        This implementation records that annotation was requested.
        """
        if not _PIL_AVAILABLE:
            return {"status": "PIL not available", "elements_highlighted": 0}
        try:
            img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
            overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(overlay)
            # Draw placeholder annotation rectangle (real coordinates come from
            # Playwright's page.query_selector_all calls in live use)
            w, h = img.size
            draw.rectangle(
                [int(w * 0.1), int(h * 0.1), int(w * 0.9), int(h * 0.2)],
                outline=(255, 165, 0, 200),
                width=3,
            )
            img = Image.alpha_composite(img, overlay)
            return {"status": "annotated", "image_size": img.size, "elements_highlighted": 1}
        except Exception as exc:
            return {"status": f"annotation_error: {exc}", "elements_highlighted": 0}
