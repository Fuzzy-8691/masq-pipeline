#!/usr/bin/env python3
"""Run bot-detection sites against patchright + camoufox. Capture
screenshots, page text, console errors, and extracted verdicts."""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

OUT = Path("/tmp/gauntlet")
OUT.mkdir(parents=True, exist_ok=True)

SITES = [
    ("sannysoft",   "https://bot.sannysoft.com/",                    8),
    ("creepjs",     "https://abrahamjuliot.github.io/creepjs/",     12),
    ("canvas",      "https://browserleaks.com/canvas",               8),
    ("pixelscan",   "https://pixelscan.net/",                       12),
    ("incolumitas", "https://bot.incolumitas.com/",                 10),
    # ── harder targets ──
    ("zillow",      "https://www.zillow.com/homes/for_sale/",       10),
    ("ticketmaster","https://www.ticketmaster.com/",                10),
    ("nopecha-cf",  "https://nopecha.com/demo/cloudflare",          12),
    ("nopecha-rc",  "https://nopecha.com/demo/recaptcha",           12),
]

NAV_TIMEOUT_MS = 45000


def extract_verdicts_sannysoft(text):
    """Pull key test rows from sannysoft page text."""
    out = {}
    for key in ("WebDriver (New)", "Chrome (New)", "Permissions (New)",
                "Plugins Length (Old)", "Languages (Old)"):
        for line in text.splitlines():
            if key in line:
                parts = line.split()
                if len(parts) >= 3:
                    out[key] = " ".join(parts[-2:])
    return out


def extract_verdicts_block(text, title=""):
    """Detect whether we got blocked or got real content."""
    low = (text or "").lower() + " " + (title or "").lower()
    blocks = [
        "access denied", "are you a robot", "unusual traffic",
        "verify you are human", "please verify", "cf-chl",
        "checking your browser", "just a moment",
        "px-captcha", "press & hold", "blocked",
        "bot detection", "attention required",
        "your browsing activity has been paused",
        "challenge required", "enable javascript and cookies",
    ]
    hits = [b for b in blocks if b in low]
    ok = [
        "for sale", "sign in", "search", "tickets", "homes",
        "buy", "sell", "login",
    ]
    ok_hits = [o for o in ok if o in low]
    return {
        "blocked": bool(hits),
        "block_signals": hits[:3],
        "content_signals": ok_hits[:3],
        "text_length": len(text),
    }


def extract_verdicts_creepjs(text):
    out = {}
    for line in text.splitlines():
        low = line.lower()
        if "trust score" in low:
            out["trust_score"] = line.strip()[:200]
        if "bot:" in low or "headless:" in low:
            out.setdefault("flags", []).append(line.strip()[:120])
    return out


async def capture_site(page, url, wait_s):
    """Returns (title, text_snippet, error, elapsed_ms)."""
    t0 = time.perf_counter()
    err = ""
    try:
        await page.goto(url, wait_until="domcontentloaded",
                        timeout=NAV_TIMEOUT_MS)
        await page.wait_for_timeout(wait_s * 1000)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"

    elapsed = int((time.perf_counter() - t0) * 1000)

    title = ""
    text = ""
    try:
        title = await page.title()
    except Exception:
        pass
    try:
        text = await page.evaluate("() => document.body.innerText || ''")
    except Exception:
        pass

    return title, text, err, elapsed


async def run_patchright():
    from patchright.async_api import async_playwright
    results = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/153.0.0.0 Safari/537.36"),
        )
        page = await ctx.new_page()

        for label, url, wait_s in SITES:
            print(f"[patchright] {label} -> {url}")
            title, text, err, ms = await capture_site(page, url, wait_s)
            try:
                await page.screenshot(
                    path=str(OUT / f"patchright_{label}.png"),
                    full_page=True,
                )
            except Exception:
                pass

            row = {"browser": "patchright", "site": label, "url": url,
                   "title": title, "elapsed_ms": ms, "error": err}
            if label == "sannysoft":
                row["verdicts"] = extract_verdicts_sannysoft(text)
            if label == "creepjs":
                row["verdicts"] = extract_verdicts_creepjs(text)
            if label in ("zillow", "ticketmaster", "nopecha-cf", "nopecha-rc"):
                row["verdicts"] = extract_verdicts_block(text, title)
            (OUT / f"patchright_{label}.txt").write_text(text[:8000])
            results.append(row)
            print(f"  title={title!r}  ms={ms}  err={err or 'none'}")

        await browser.close()
    return results


async def run_camoufox():
    from camoufox.async_api import AsyncCamoufox
    results = []

    async with AsyncCamoufox(headless=True) as browser:
        page = await browser.new_page()

        for label, url, wait_s in SITES:
            print(f"[camoufox] {label} -> {url}")
            title, text, err, ms = await capture_site(page, url, wait_s)
            try:
                await page.screenshot(
                    path=str(OUT / f"camoufox_{label}.png"),
                    full_page=True,
                )
            except Exception:
                pass

            row = {"browser": "camoufox", "site": label, "url": url,
                   "title": title, "elapsed_ms": ms, "error": err}
            if label == "sannysoft":
                row["verdicts"] = extract_verdicts_sannysoft(text)
            if label == "creepjs":
                row["verdicts"] = extract_verdicts_creepjs(text)
            if label in ("zillow", "ticketmaster", "nopecha-cf", "nopecha-rc"):
                row["verdicts"] = extract_verdicts_block(text, title)
            (OUT / f"camoufox_{label}.txt").write_text(text[:8000])
            results.append(row)
            print(f"  title={title!r}  ms={ms}  err={err or 'none'}")

    return results


def run_cloakbrowser():
    """CloakBrowser uses the sync Playwright API — run it in a thread."""
    from cloakbrowser import launch

    results = []
    browser = launch(headless=True)
    try:
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()

        for label, url, wait_s in SITES:
            print(f"[cloakbrowser] {label} -> {url}")
            t0 = time.perf_counter()
            err = ""
            title = ""
            text = ""
            try:
                page.goto(url, wait_until="domcontentloaded",
                          timeout=NAV_TIMEOUT_MS)
                page.wait_for_timeout(wait_s * 1000)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
            elapsed = int((time.perf_counter() - t0) * 1000)

            try:
                title = page.title()
            except Exception:
                pass
            try:
                text = page.evaluate("() => document.body.innerText || ''")
            except Exception:
                pass

            try:
                page.screenshot(
                    path=str(OUT / f"cloakbrowser_{label}.png"),
                    full_page=True,
                )
            except Exception:
                pass

            row = {"browser": "cloakbrowser", "site": label, "url": url,
                   "title": title, "elapsed_ms": elapsed, "error": err}
            if label == "sannysoft":
                row["verdicts"] = extract_verdicts_sannysoft(text)
            if label == "creepjs":
                row["verdicts"] = extract_verdicts_creepjs(text)
            if label in ("zillow", "ticketmaster", "nopecha-cf", "nopecha-rc"):
                row["verdicts"] = extract_verdicts_block(text, title)
            (OUT / f"cloakbrowser_{label}.txt").write_text(text[:8000])
            results.append(row)
            print(f"  title={title!r}  ms={elapsed}  err={err or 'none'}")
    finally:
        try:
            browser.close()
        except Exception:
            pass
    return results


async def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    results = []

    if which in ("all", "patchright"):
        try:
            results += await run_patchright()
        except Exception as e:
            print(f"[!] patchright crashed: {e}")
            results.append({"browser": "patchright", "site": "*",
                            "error": str(e)})

    if which in ("all", "camoufox"):
        try:
            results += await run_camoufox()
        except Exception as e:
            print(f"[!] camoufox crashed: {e}")
            results.append({"browser": "camoufox", "site": "*",
                            "error": str(e)})

    if which in ("all", "cloakbrowser"):
        try:
            cb = await asyncio.to_thread(run_cloakbrowser)
            results += cb
        except Exception as e:
            print(f"[!] cloakbrowser crashed: {e}")
            results.append({"browser": "cloakbrowser", "site": "*",
                            "error": str(e)})

    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    print()
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    for r in results:
        print(f"  {r.get('browser','?'):<12} {r.get('site','?'):<12} "
              f"{r.get('elapsed_ms','-'):>6}ms  {r.get('title','')[:50]}")
    print()
    print(f"artifacts in {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
