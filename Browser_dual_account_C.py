#!/usr/bin/env python3
"""
GL_dual_accounts.py — encrypted lookmovie2 → TeraBox, multi-account + ghost edition.

FORK OF dual_account.py

Adds:
  - Per-account .env handling (3 accounts, self-heal per account).
  - Manifest CSV logging every successful upload (uploads.csv).
  - Ghost mode: encrypt once, split ciphertext into 3 shards, scatter one
    shard to each of accounts 1/2/3. Reconstruct by downloading all 3
    shards (3 sequential Chrome sessions) and reassembling.

.env layout:
  TERABOX_1_USERNAME / TERABOX_1_PASSWORD / TERABOX_1_COOKIE
  TERABOX_2_USERNAME / TERABOX_2_PASSWORD / TERABOX_2_COOKIE
  TERABOX_3_USERNAME / TERABOX_3_PASSWORD / TERABOX_3_COOKIE

Legacy fallback for account 1 (still works, transitions on first heal):
  TERABOX_USERNAME / TERABOX_PASSWORD / COOKIE_JSON (or NDUS)

Ghost shard format (on TeraBox, per account):
  <ghost_dir>/<mask>.part<N>of<M>.bin
  header (60 bytes): MAGIC(9) ver(1) idx(1) total(1) ghost_id(32) total_ct_len(8) payload_len(8)

Encryption: AES-256-GCM, PBKDF2-SHA256 600k master, HKDF per-file key.
"""

import argparse
import asyncio
import base64
import csv
import datetime
import getpass
import hashlib
import hmac as stdhmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import random
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import requests
from dotenv import load_dotenv
#from patchright.async_api import async_playwright
from patchright.async_api import async_playwright

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================
# config
# ============================================================
STREAM_EXTS = (".m3u8", ".mpd")
UA_CAPTURE = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
UA_UPLOAD = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

CHUNK_SIZE = 4 * 1024 * 1024
UPLOAD_MAX_RETRIES = 3
UPLOAD_RETRY_DELAY = 5

WEB_HOST = "https://www.terabox.com"
UPLOAD_HOST = "https://c-all.terabox.com"
APP_ID = "250528"
CHANNEL = "dubox"
CLIENTTYPE = "0"
WEB = "1"
TOKEN_KEYS = ["jsToken", "dp-logid", "app_id", "appId", "bdstoken"]

PASSWORD_TAB_SELECTORS = [
    'text=Password login',
    'text=Password Login',
    'text=密码登录',
    '[role="tab"]:has-text("Password")',
]
USERNAME_SELECTORS = [
    'input[name="userName"]',
    'input[name="username"]',
    'input[placeholder*="mail" i]',
    'input[placeholder*="ccount" i]',
    'input[placeholder*="hone" i]',
    'input[type="email"]',
    'input[type="text"]',
]
PASSWORD_SELECTORS = ['input[name="password"]', 'input[type="password"]']
SUBMIT_SELECTORS = [
    'button:has-text("Sign in")',
    'button:has-text("Log in")',
    'button:has-text("Login")',
    'button:has-text("登录")',
    'button[type="submit"]',
]
DEFAULT_REMOTE_ROOT = os.environ.get("DEFAULT_REMOTE_ROOT", "/_Rescue_Uploads")

MAX_RAM_BYTES = 2 * 1024 * 1024 * 1024
MAX_RAM_BYTES_ENCRYPT = 1 * 1024 * 1024 * 1024

MAX_COOKIE_HISTORY = 10
NUM_ACCOUNTS = 3

DLINK_PATTERNS = [
    r"https?://d(-[a-z]{2,5})?\.terabox\.com/file/[^\s\"'<>\\]+",
    r"https?://data(-[a-z]{2,5})?\.terabox\.com/file/[^\s\"'<>\\]+",
    r"https?://d(-[a-z]{2,5})?\.1024tera\.com/file/[^\s\"'<>\\]+",
    r"https?://d(-[a-z]{2,5})?\.terabox\.app/file/[^\s\"'<>\\]+",
]
DLINK_KEYS = ["dlink", "downloadLink", "download_link", "direct_link"]
DEFAULT_DOWNLOAD_DIR = os.environ.get("DOWNLOAD_DIR", "/Volumes/Backup_Plus/LookMovie_TEST/Encrypt_Decrypt")
DOWNLOAD_WATCH_TIMEOUT = 180
DOWNLOAD_CAPTURE_GRACE = 5

APP_SALT = b"ee_tb_vs_app_salt_v1_\x00\x00"
HKDF_INFO = b"ee_tb_vs_file_key_v1"
PBKDF2_ITERS = 600_000
SALT_LEN = 16
NONCE_LEN = 12

# ghost mode
GHOST_MAGIC = b"EETBGHOST"
GHOST_VERSION = 1
GHOST_SHARD_COUNT = 3
GHOST_ID_LEN = 32
# header layout: MAGIC(9) + ver(1) + idx(1) + total(1) + ghost_id(32)
#              + total_ct_len(8) + payload_len(8) = 60
GHOST_HEADER_LEN = len(GHOST_MAGIC) + 3 + GHOST_ID_LEN + 8 + 8

# manifest
MANIFEST_PATH = Path(os.environ.get("MANIFEST_PATH", "/Volumes/Backup_Plus/BROWSER_TEST/uploads.csv"))
MANIFEST_HEADERS = [
    "timestamp", "account", "type", "orig_name", "masked_name",
    "size", "remote_dir", "fs_id",
    "ghost_id", "ghost_shard", "ghost_total", "ghost_original_size",
]

# session-scoped
ACTIVE_ACCOUNT: int = 1
TERABOX_USERNAME: str = ""
TERABOX_PASSWORD: str = ""
master_key: bytes | None = None
uploaded_md5s: dict[str, str] = {}
sniffed_tokens: dict[str, str] = {}

#ENV_PATH = Path("/Users/myrnasorellepambou/Desktop/android_file/.env")


ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(ENV_PATH)



# ============================================================
# .env reader (handles inline comments + mid-session rewrites)
# ============================================================
def _read_env_value(key: str) -> str:
    try:
        content = ENV_PATH.read_text()
    except Exception:
        return ""
    pat = re.compile(rf"^{re.escape(key)}\s*=\s*(.*)$")
    for ln in content.splitlines():
        stripped = ln.lstrip()
        if stripped.startswith("#"):
            continue
        m = pat.match(stripped)
        if m:
            val = m.group(1)
            if " #" in val:
                val = val.split(" #", 1)[0]
            return val.strip().strip('"').strip("'")
    return ""


def _env_key_present(key: str) -> bool:
    try:
        content = ENV_PATH.read_text()
    except Exception:
        return False
    return bool(re.search(rf"^{re.escape(key)}\s*=", content, re.M))


# ============================================================
# manifest
# ============================================================
def append_manifest(rows: list[dict]) -> None:
    """Append rows to uploads.csv. Creates header on first write."""
    if not rows:
        return
    try:
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        new_file = not MANIFEST_PATH.exists()
        with MANIFEST_PATH.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=MANIFEST_HEADERS)
            if new_file:
                writer.writeheader()
            for row in rows:
                full = {k: row.get(k, "") for k in MANIFEST_HEADERS}
                writer.writerow(full)
    except Exception as e:
        print(f"  ⚠️  manifest write failed: {e}")


def _extract_fs_id(resp: dict) -> str:
    info = resp.get("info")
    if isinstance(info, list) and info:
        return str(info[0].get("fs_id", ""))
    if isinstance(info, dict):
        return str(info.get("fs_id", ""))
    return str(resp.get("fs_id", ""))



# ============================================================
# account resolution
# ============================================================
# ============================================================
# notifications  (macOS osascript · Discord webhook · terminal bell)
# ============================================================
NOTIFY_LEVEL_COLORS = {
    "info":    0x3498DB,
    "success": 0x2ECC71,
    "warn":    0xF1C40F,
    "error":   0xE74C3C,
}

_JOB_START: float = 0.0
_JOB_LABEL: str = ""
_JOB_NOTIFIED: bool = False


def _notify_mode() -> str:
    raw = (os.getenv("NOTIFY", "") or _read_env_value("NOTIFY")).strip().lower()
    if raw in ("macos", "discord", "both", "none", "bell"):
        return raw
    return "macos" if sys.platform == "darwin" else "bell"


def _notify_verbose() -> bool:
    v = (os.getenv("NOTIFY_VERBOSE", "")
         or _read_env_value("NOTIFY_VERBOSE")).strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _discord_webhook() -> str:
    return (os.getenv("DISCORD_WEBHOOK_URL", "")
            or _read_env_value("DISCORD_WEBHOOK_URL")).strip()


def _fmt_duration(seconds: float) -> str:
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s"


def _notify_macos(title: str, body: str) -> bool:
    msg = f"{title} — {body}".replace("\n", " · ")

    # Preferred: terminal-notifier (own app identity → no Terminal.app
    # notification permission needed). Fallback: osascript.
    tn = shutil.which("terminal-notifier")
    if tn:
        try:
            subprocess.run(
                [tn, "-title", "MASQ FLOW", "-message", msg,
                 "-sound", "default"],
                check=True, capture_output=True, timeout=5,
            )
            return True
        except Exception as e:
            if _notify_verbose():
                print(f"  [notify] terminal-notifier failed: {e} — "
                      f"falling back to osascript")

    # Fallback: raw osascript
    safe = msg.replace('"', "'").replace("\\", "/")
    script = f'display notification "{safe}" with title "MASQ FLOW"'
    try:
        subprocess.run(
            ["osascript", "-e", script],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except Exception as e:
        if _notify_verbose():
            print(f"  [notify] macOS failed: {e}")
        return False


def _notify_discord(title: str, body: str, level: str) -> bool:
    url = _discord_webhook()
    if not url:
        if _notify_verbose():
            print("  [notify] Discord: DISCORD_WEBHOOK_URL not set")
        return False
    payload = {
        "embeds": [{
            "title": title,
            "description": body,
            "color": NOTIFY_LEVEL_COLORS.get(level, 0x95A5A6),
            "footer": {"text": "MASQ FLOW"},
            "timestamp": iso_now(),
        }]
    }
    try:
        r = requests.post(url, json=payload, timeout=8)
        r.raise_for_status()
        return True
    except Exception as e:
        if _notify_verbose():
            print(f"  [notify] Discord failed: {e}")
        return False


def _notify_bell() -> None:
    try:
        sys.stdout.write("\a")
        sys.stdout.flush()
    except Exception:
        pass


def notify(title: str, body: str, level: str = "info") -> None:
    """Fire a notification via the configured channel(s)."""
    mode = _notify_mode()
    if mode == "none":
        return
    if mode == "bell":
        _notify_bell()
        if _notify_verbose():
            print(f"  [notify/bell] {level}: {title}")
        return

    sent = False
    if mode in ("macos", "both"):
        if _notify_macos(title, body):
            sent = True
    if mode in ("discord", "both"):
        if _notify_discord(title, body, level):
            sent = True
    if not sent:
        _notify_bell()

    if _notify_verbose():
        tag = "sent" if sent else "fell-back-to-bell"
        print(f"  [notify/{mode}] {level} ({tag}): {title}")


def _start_job(label: str) -> None:
    """Begin a tracked job. Call at the top of each long-running run_* fn."""
    global _JOB_START, _JOB_LABEL, _JOB_NOTIFIED
    _JOB_START = time.time()
    _JOB_LABEL = label
    _JOB_NOTIFIED = False


def notify_job_end(status: str, detail: str = "") -> None:
    """Fire a notification for the current job. Idempotent per job.

    status: 'complete' | 'partial' | 'failed' | 'aborted' | 'no-op'
    """
    global _JOB_NOTIFIED
    if _JOB_NOTIFIED:
        return
    _JOB_NOTIFIED = True

    dur = _fmt_duration(time.time() - _JOB_START) if _JOB_START else "?"
    label = _JOB_LABEL or "Job"

    if status in ("complete", "ok"):
        level, headline = "success", f"{label} complete"
    elif status == "partial":
        level, headline = "warn", f"{label} partial"
    elif status == "aborted":
        level, headline = "warn", f"{label} aborted"
    elif status == "failed":
        level, headline = "error", f"{label} failed"
    elif status == "no-op":
        level, headline = "info", f"{label} no-op"
    else:
        level, headline = "info", f"{label}: {status}"

    body = f"{detail} · {dur}".strip(" ·") if detail else dur
    notify(headline, body, level)


# ============================================================
# account resolution
# ============================================================
def load_accounts_from_env() -> dict[int, dict[str, str]]:
    accounts: dict[int, dict[str, str]] = {}
    for n in range(1, NUM_ACCOUNTS + 1):
        u = _read_env_value(f"TERABOX_{n}_USERNAME")
        p = _read_env_value(f"TERABOX_{n}_PASSWORD")
        c = _read_env_value(f"TERABOX_{n}_COOKIE")
        if n == 1:
            if not u:
                u = _read_env_value("TERABOX_USERNAME")
            if not p:
                p = _read_env_value("TERABOX_PASSWORD")
            if not c:
                c = _read_env_value("COOKIE_JSON") or _read_env_value("NDUS")
        accounts[n] = {"username": u, "password": p, "cookie": c}
    return accounts


def _mask_username(u: str) -> str:
    if not u:
        return "(unset)"
    local, _, domain = u.partition("@")
    if domain:
        head = local[:2] if len(local) >= 2 else local[:1]
        return f"{head}***@{domain}"
    return (u[:3] + "***") if len(u) > 3 else u + "***"


def set_active_account(n: int) -> None:
    global ACTIVE_ACCOUNT, TERABOX_USERNAME, TERABOX_PASSWORD
    accounts = load_accounts_from_env()
    if n not in accounts:
        raise ValueError(f"unknown account {n}")
    a = accounts[n]
    ACTIVE_ACCOUNT = n
    TERABOX_USERNAME = a["username"]
    TERABOX_PASSWORD = a["password"]
    if not a["username"] or not a["password"]:
        print(f"  ⚠️  account {n} is missing username/password in .env")
    if not a["cookie"]:
        print(f"  ⚠️  account {n} has no cookie — manual login will be required")


def prompt_account_choice() -> int:
    accounts = load_accounts_from_env()

    _section("ACCOUNT")
    for n in range(1, NUM_ACCOUNTS + 1):
        a = accounts[n]
        active = (n == 1)
        m   = f"{_C}{_B}◉{_X}" if active else f"{_D}○{_X}"
        n_s = f"{_C}{_B}{n}{_X}" if active else f"{_D}{n}{_X}"
        shown = _mask_username(a["username"])
        shown_c = shown if active else f"{_D}{shown}{_X}"
        has_c = f"{_G}✓{_X}" if a["cookie"] else f"{_R}✗{_X}"
        cnote = f"({len(a['cookie'])}c)" if a["cookie"] else ""
        print(f"    {m}  {n_s}  {shown_c:<28}  "
            f"{_D}cookie{_X} {has_c}  {_D}{cnote}{_X}")

    while True:
        try:
            choice = input(_ask_line("which account", "[1]")).strip() or "1"
        except (KeyboardInterrupt, EOFError):
            print()
            raise KeyboardInterrupt()
        if choice in [str(i) for i in range(1, NUM_ACCOUNTS + 1)]:
            return int(choice)
        _ask_error(f"enter 1..{NUM_ACCOUNTS}")

def _redact_path(p: Path) -> str:
    """Ghost mode: show only the filename, never the real location."""
    return p.name

# ============================================================
# prompt styling — single-line, circles for choices
# ============================================================
_C, _D, _B, _G, _Y, _R, _X = (
    "\033[96m", "\033[90m", "\033[1m",
    "\033[92m", "\033[93m", "\033[91m", "\033[0m",
)

def _section(title: str) -> None:
    W = 60
    pad = max(1, W - len(title) - 5)
    print()
    print(f"  {_D}──{_X} {_C}{_B}{title}{_X} {_D}{'─' * pad}{_X}")

def _ask_yn(prompt: str, default_yes: bool = True) -> str:
    """Single-line yes/no with inline ◉/○ radios."""
    radios = (
        f"{_C}{_B}◉ Y{_X}  {_D}○ n{_X}" if default_yes
        else f"{_D}○ y{_X}  {_C}{_B}◉ N{_X}"
    )
    return f"  {_C}{_B}●{_X} {prompt}    {radios}  {_D}›{_X} "

def _ask_pick(prompt: str, options: list[tuple[str, str]],
              default: str = "1") -> str:
    """Single-line choice with inline ◉/○ radios."""
    parts = []
    for num, label in options:
        active = (num == default)
        m   = f"{_C}{_B}◉{_X}" if active else f"{_D}○{_X}"
        n   = f"{_C}{_B}{num}{_X}" if active else f"{_D}{num}{_X}"
        lbl = label if active else f"{_D}{label}{_X}"
        parts.append(f"{m} {n}·{lbl}")
    return f"  {_C}{_B}●{_X} {prompt}   {'   '.join(parts)}  {_D}›{_X} "

def _ask_line(prompt: str, hint: str = "") -> str:
    """Single-line styled text input prompt."""
    h = f"  {_D}{hint}{_X}" if hint else ""
    return f"  {_C}{_B}●{_X} {prompt}{h}  {_D}›{_X} "

def _ask_error(msg: str) -> None:
    print(f"  {_R}✗{_X}  {_R}{msg}{_X}")

def print_creds_diagnostic(animated=True) -> bool:
    # ── palette ──
    C  = "\033[96m"   # cyan frame (healthy)
    Y  = "\033[93m"   # yellow (bar partial)
    G  = "\033[92m"   # green  (all present)
    BG = "\033[1;92m" # bright bold green (success flash)
    R  = "\033[91m"   # red    (missing / error)
    D  = "\033[90m"   # dim labels
    B  = "\033[1m"    # bold
    X  = "\033[0m"

    # ── animation timings — tune to taste ──
    INTEL_SECONDS   = 5.0     # intel bar fill duration
    ACCOUNT_SECONDS = 5.0     # per-account reveal (split across 4 sub-stages)
    FPS             = 30
    FLASH_PERIOD    = 0.16    # on/off toggle for error border flash

    # escape hatch: MASQ_NO_ANIM=1 python GL_dual_accounts.py
    if os.environ.get("MASQ_NO_ANIM") == "1":
        animated = False

    W = 60
    _ANSI = re.compile(r"\033\[[0-9;]*m")

    def _wide(ch):
        o = ord(ch)
        return (
            0x1100 <= o <= 0x115F or
            0x2E80 <= o <= 0xA4CF or
            0xAC00 <= o <= 0xD7A3 or
            0xF900 <= o <= 0xFAFF or
            0xFE30 <= o <= 0xFE4F or
            0xFF00 <= o <= 0xFF60 or
            0xFFE0 <= o <= 0xFFE6 or
            0x1F300 <= o <= 0x1FAFF
        )

    def vis(s):
        return sum(2 if _wide(c) else 1 for c in _ANSI.sub("", s))

    def fit(s, width):
        return s + " " * max(0, width - vis(s))

    ok  = f"{G}✓{X}"
    bad = f"{R}✗{X}"

    # ── env check (silent — no path display) ──
    if not ENV_PATH.exists():
        print(f"{R}┌{'─' * W}┐{X}")
        print(f"{R}│{X}" + fit(f"  {B}◆ CREDENTIALS CHECK{X}", W) + f"{R}│{X}")
        print(f"{R}├{'─' * W}┤{X}")
        print(f"{R}│{X}" + fit(f"  {R}{B}▸ ERROR{X}   {R}no .env file{X}", W) + f"{R}│{X}")
        print(f"{R}└{'─' * W}┘{X}")
        print()
        return False

    # ── gather credential presence ──
    rows_data = []
    total = NUM_ACCOUNTS * 3
    present = 0
    for n in range(1, NUM_ACCOUNTS + 1):
        u = _env_key_present(f"TERABOX_{n}_USERNAME")
        p = _env_key_present(f"TERABOX_{n}_PASSWORD")
        c = _env_key_present(f"TERABOX_{n}_COOKIE")
        if n == 1:
            u = u or _env_key_present("TERABOX_USERNAME")
            p = p or _env_key_present("TERABOX_PASSWORD")
            c = c or _env_key_present("COOKIE_JSON")
        present += int(bool(u)) + int(bool(p)) + int(bool(c))
        rows_data.append((n, u, p, c))

    accounts = load_accounts_from_env()

    BAR_W = 20
    complete = (present == total)

    # ── line builders ──
    def intel_line(progress):
        final_filled = BAR_W * present / total if total else 0
        filled = int(round(final_filled * progress))
        if present == total:
            bar_color = G
        elif present >= total * 2 // 3:
            bar_color = Y
        else:
            bar_color = R
        bar = f"{bar_color}{'▓' * filled}{D}{'░' * (BAR_W - filled)}{X}"
        shown = int(round(present * progress))
        status = (ok if present == total else bad) if progress >= 1.0 else " "
        return f"  {D}INTEL{X}  {bar}  {status}  {D}{shown}/{total}{X}"

    def account_line(idx, stage):
        """stage: -1=hidden, 0=labels only, 1=+user, 2=+pass, 3=+cookie"""
        if stage < 0:
            return ""
        n, u_present, p_present, c_present = rows_data[idx]
        cval = accounts[n]["cookie"]
        cnote = f"({len(cval)}c)" if cval else ""
        u_mark = (ok if u_present else bad) if stage >= 1 else " "
        p_mark = (ok if p_present else bad) if stage >= 2 else " "
        c_mark = (ok if c_present else bad) if stage >= 3 else " "
        cnote_display = cnote if stage >= 3 else " " * len(cnote)
        return (
            f"  {D}[{n}]{X}  Terabox_{n:<10}"
            f"  {D}user{X} {u_mark}"
            f"   {D}pass{X} {p_mark}"
            f"   {D}cookie{X} {c_mark}"
            f"  {D}{cnote_display}{X}"
        )

    def build_alert_lines():
        details = []
        for n, u, p, c in rows_data:
            bits = []
            if not u: bits.append("user")
            if not p: bits.append("pass")
            if not c: bits.append("cookie")
            if bits:
                details.append(f"[{n}] {' '.join(bits)}")
        line1 = f"  {R}{B}▸ ERROR{X}   {R}missing credentials{X}"
        line2 = f"    {D}{'  ·  '.join(details)}{X}"
        return [line1, line2]

    def build_panel(intel_progress, account_stages, border=None, alert=None, hard=False):
        b = border if border is not None else C

        if hard:
            # solid bars — every border, divider, and side wall becomes █
            bar      = f"{b}{'█' * (W + 2)}{X}"
            top_f    = bar
            mid_f    = bar
            bottom_f = bar

            def row_f(s=""):
                return f"{b}█{X}" + fit(s, W) + f"{b}█{X}"
        else:
            top_f    = f"{b}┌{'─' * W}┐{X}"
            mid_f    = f"{b}├{'─' * W}┤{X}"
            bottom_f = f"{b}└{'─' * W}┘{X}"

            def row_f(s=""):
                return f"{b}│{X}" + fit(s, W) + f"{b}│{X}"

        lines = [
            top_f,
            row_f(f"  {B}◆ CREDENTIALS CHECK{X}"),
            mid_f,
            row_f(intel_line(intel_progress)),
            mid_f,
        ]
        for i, stage in enumerate(account_stages):
            lines.append(row_f(account_line(i, stage)))
        if alert:
            lines.append(mid_f)
            for al in alert:
                lines.append(row_f(al))
        lines.append(bottom_f)
        return lines

    # ── non-animated path ──
    if not animated or not sys.stdout.isatty():
        alert = build_alert_lines() if not complete else None
        border = R if not complete else None
        for line in build_panel(1.0, [3] * len(rows_data), border=border, alert=alert):
            print(line)
        print()
        return complete

    # ── animated path ──
    initial_stages = [-1] * len(rows_data)
    initial_panel  = build_panel(0.0, initial_stages)
    frame_dt = 1.0 / FPS

    def repaint(lines, h):
        sys.stdout.write(f"\033[{h}A")
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    print("\033[?25l", end="")   # hide cursor during boot
    try:
        h = len(initial_panel)
        print("\n".join(initial_panel))
        sys.stdout.flush()

        # ── PHASE 1: intel bar fills ──
        t0 = time.time()
        while True:
            elapsed = time.time() - t0
            progress = min(1.0, elapsed / INTEL_SECONDS)
            panel = build_panel(progress, initial_stages)
            repaint(panel, h)
            if progress >= 1.0:
                break
            time.sleep(frame_dt)

        time.sleep(0.25)

        # ── PHASE 2: accounts reveal, marks one-by-one ──
        stage_dt = ACCOUNT_SECONDS / 4.0
        current  = list(initial_stages)
        last_i   = len(rows_data) - 1

        for i in range(len(rows_data)):
            current[i] = 0
            repaint(build_panel(1.0, current), h)
            time.sleep(stage_dt)
            for stage in (1, 2, 3):
                current[i] = stage
                repaint(build_panel(1.0, current), h)
                if not (i == last_i and stage == 3):
                    time.sleep(stage_dt)

        # ── PHASE 3: error alert (only if incomplete) ──
        if not complete:
            alert   = build_alert_lines()
            settled = build_panel(1.0, [3] * len(rows_data), border=R, alert=alert)
            new_h   = len(settled)

            grown = build_panel(1.0, [3] * len(rows_data), border=C, alert=alert)
            repaint(grown, h)
            time.sleep(0.35)

            for i in range(6):
                bc = R if i % 2 == 0 else C
                flash = build_panel(1.0, [3] * len(rows_data), border=bc, alert=alert)
                repaint(flash, new_h)
                time.sleep(FLASH_PERIOD)

            repaint(settled, new_h)
            time.sleep(0.7)
            h = new_h
        else:
            # ── PHASE 3: success pulse (single hard green flash) ──
            settled = build_panel(1.0, [3] * len(rows_data), border=C)
            hard    = build_panel(1.0, [3] * len(rows_data), border=BG, hard=True)

            # one bright slam, then settle
            repaint(hard, h)
            time.sleep(0.35)
            repaint(settled, h)
            time.sleep(0.45)

    finally:
        print("\033[?25h", end="")   # restore cursor
    print()
    return complete

# ============================================================
# generic helpers
# ============================================================
def ask_yes_no(prompt: str, default_yes: bool = True) -> bool:
    if os.getenv("PIPELINE_NONINTERACTIVE") == "1":
        print(f"  [auto] {prompt.strip()} -> {'yes' if default_yes else 'no'}")
        return default_yes
    try:
        ans = input(_ask_yn(prompt, default_yes)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        raise KeyboardInterrupt()
    if not ans:
        return default_yes
    return ans in ("y", "yes")


def sanitize(s: str) -> str:
    return re.sub(r"[^\w\- ]", "", s).strip().replace(" ", "_") or "untitled"


def human_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def parse_episode_range(spec: str) -> list[int]:
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                lo, hi = int(a), int(b)
                if lo > hi:
                    lo, hi = hi, lo
                out.update(range(lo, hi + 1))
        elif chunk.isdigit():
            out.add(int(chunk))
    return sorted(out)


def iso_now() -> str:
    return (
        datetime.datetime.now(datetime.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# encryption
# ============================================================
def prompt_passphrase(confirm: bool = True) -> str:
    env_pw = os.getenv("EE_TB_PASSPHRASE")
    if env_pw:
        print("  🔐 passphrase read from EE_TB_PASSPHRASE env")
        return env_pw

    print()
    print("=" * 62)
    print("  ENCRYPTION")
    print("=" * 62)
    print("  Files are encrypted client-side before upload.")
    print("  TeraBox only ever sees AES-256-GCM ciphertext.")
    print()
    print("  ⚠️  If you lose the passphrase, files cannot be recovered.")
    print("      There is no reset, no backdoor, no admin override.")
    print("=" * 62)
    print()

    while True:
        pw = getpass.getpass("  passphrase: ")
        if not pw:
            print("  (empty — try again)")
            continue
        if not confirm:
            return pw
        pw2 = getpass.getpass("  confirm  : ")
        if pw == pw2:
            return pw
        print("  ⚠️  passphrases don't match — try again\n")


def derive_master(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=APP_SALT,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derive_file_key(master: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(master)


def mask_name(master: bytes, show: str, season: int, episode: int) -> str:
    msg = f"{sanitize(show)}|S{int(season):02d}E{int(episode):02d}".encode("utf-8")
    key = stdhmac.new(master, b"ee_tb_filename_v1", hashlib.sha256).digest()
    digest = stdhmac.new(key, msg, hashlib.sha256).hexdigest()
    return digest[:32] + ".bin"


def mask_name_movie(master: bytes, title: str, year: str = "") -> str:
    key = stdhmac.new(master, b"ee_tb_filename_v1", hashlib.sha256).digest()
    msg = f"MOVIE|{sanitize(title)}|{year}".encode("utf-8")
    digest = stdhmac.new(key, msg, hashlib.sha256).hexdigest()
    return digest[:32] + ".bin"


def encrypt_blob(
    plaintext_chunks: list[bytes],
    metadata: dict[str, object],
    master: bytes,
) -> bytes:
    meta_json = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    if len(meta_json) > 0xFFFFFFFF:
        raise ValueError("metadata too large")

    plaintext = (
        len(meta_json).to_bytes(4, "little")
        + meta_json
        + b"".join(plaintext_chunks)
    )
    plaintext_chunks.clear()

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    file_key = derive_file_key(master, salt)
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    del plaintext
    return salt + nonce + ciphertext


def decrypt_blob(encrypted: bytes, passphrase: str) -> tuple[dict[str, object], bytes]:
    if len(encrypted) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("encrypted blob too short")

    salt = encrypted[:SALT_LEN]
    nonce = encrypted[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = encrypted[SALT_LEN + NONCE_LEN:]

    master = derive_master(passphrase)
    file_key = derive_file_key(master, salt)
    aesgcm = AESGCM(file_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    if len(plaintext) < 4:
        raise ValueError("decrypted payload too short for metadata header")
    meta_len = int.from_bytes(plaintext[:4], "little")
    if 4 + meta_len > len(plaintext):
        raise ValueError("metadata length exceeds payload")

    metadata = json.loads(plaintext[4:4 + meta_len].decode("utf-8"))
    video = plaintext[4 + meta_len:]
    return metadata, video


# ============================================================
# ghost shards
# ============================================================
def pack_shard_header(shard_idx: int, total: int, ghost_id: str,
                      total_ct_len: int, payload_len: int) -> bytes:
    gid_bytes = ghost_id.encode("ascii")[:GHOST_ID_LEN].ljust(GHOST_ID_LEN, b"\x00")
    return (
        GHOST_MAGIC
        + bytes([GHOST_VERSION, shard_idx, total])
        + gid_bytes
        + total_ct_len.to_bytes(8, "little")
        + payload_len.to_bytes(8, "little")
    )


def unpack_shard_header(blob: bytes) -> dict:
    if not blob.startswith(GHOST_MAGIC):
        raise ValueError("not a ghost shard (bad magic)")
    off = len(GHOST_MAGIC)
    version = blob[off]; off += 1
    shard_idx = blob[off]; off += 1
    total = blob[off]; off += 1
    ghost_id = blob[off:off + GHOST_ID_LEN].rstrip(b"\x00").decode("ascii")
    off += GHOST_ID_LEN
    total_ct_len = int.from_bytes(blob[off:off + 8], "little"); off += 8
    payload_len = int.from_bytes(blob[off:off + 8], "little"); off += 8
    return {
        "version": version,
        "shard_idx": shard_idx,
        "total": total,
        "ghost_id": ghost_id,
        "total_ct_len": total_ct_len,
        "payload_len": payload_len,
        "header_len": off,
    }


def split_ghost(ciphertext: bytes, ghost_id: str,
                n: int = GHOST_SHARD_COUNT) -> list[bytes]:
    total_len = len(ciphertext)
    base = total_len // n
    remainder = total_len % n
    shards = []
    offset = 0
    for i in range(n):
        size = base + (1 if i < remainder else 0)
        payload = ciphertext[offset:offset + size]
        offset += size
        header = pack_shard_header(i, n, ghost_id, total_len, size)
        shards.append(header + payload)
    return shards


def reassemble_ghost(shard_blobs: list[bytes]) -> tuple[str, bytes]:
    parsed = []
    for blob in shard_blobs:
        h = unpack_shard_header(blob)
        h["blob"] = blob
        parsed.append(h)
    if not parsed:
        raise ValueError("no shards")

    ghost_id = parsed[0]["ghost_id"]
    total = parsed[0]["total"]
    total_ct_len = parsed[0]["total_ct_len"]
    for h in parsed:
        if h["ghost_id"] != ghost_id:
            raise ValueError(f"ghost_id mismatch: {h['ghost_id']} vs {ghost_id}")
        if h["total"] != total:
            raise ValueError(f"total mismatch: {h['total']} vs {total}")
        if h["total_ct_len"] != total_ct_len:
            raise ValueError("total_ct_len mismatch")

    if len(parsed) != total:
        raise ValueError(f"need {total} shards, got {len(parsed)}")

    parsed.sort(key=lambda h: h["shard_idx"])
    indices = [h["shard_idx"] for h in parsed]
    if len(set(indices)) != len(indices):
        counts: dict[int, int] = {}
        for h in parsed:
            counts[h["shard_idx"]] = counts.get(h["shard_idx"], 0) + 1
        dupes = {k: v for k, v in counts.items() if v > 1}
        raise ValueError(
            f"duplicate shard indices {dupes} — one or more local files "
            f"is a duplicate of another (got indices {indices})"
        )
    if indices != list(range(total)):
        raise ValueError(f"shard indices not sequential: {indices}")
    parts = []
    for h in parsed:
        payload = h["blob"][h["header_len"]:]
        if len(payload) != h["payload_len"]:
            raise ValueError(f"shard {h['shard_idx']} payload_len mismatch")
        parts.append(payload)

    ct = b"".join(parts)
    if len(ct) != total_ct_len:
        raise ValueError(f"reassembled length {len(ct)} != expected {total_ct_len}")
    return ghost_id, ct


def shard_filename(ghost_id: str, idx: int, total: int) -> str:
    return f"{ghost_id}.part{idx}of{total}.bin"


# ============================================================
# capture helpers
# ============================================================
async def click_play(page):
    """Click the initial play button.

    Tries the show-page external-player link and the round-button overlay
    first (these open the /play/ page hosting the real stream), then falls
    through to inline player selectors. Requires visible so we skip hidden
    stubs left in the DOM after navigation.
    """
    for sel in [
        '#shows-external-player-link',
        '.round-button',
        'button[aria-label*="play" i]',
        'button:has-text("Play")',
        '.play-button',
        '.vjs-big-play-button',
        '.jw-icon-playback',
        '[class*="play" i]',
        'video',
    ]:
        try:
            el = page.locator(sel).first
            if await el.count() > 0 and await el.is_visible():
                await el.click(timeout=4000, force=True)
                print(f"    [play] clicked {sel}")
                return True
        except Exception:
            continue
    print(f"    [play] no play button matched")
    return False


def _strip_overlay_js() -> str:
    return """
        () => {
            document.querySelectorAll('.pre-init-ads--loading-please-wait')
                .forEach(el => el.remove());
            document.querySelectorAll('#PlayerZone a[href="/premium.html"]')
                .forEach(el => el.remove());
            document.querySelectorAll('.tw-z-50').forEach(el => {
                const s = getComputedStyle(el);
                if (s.position === 'absolute' && s.inset === '0px') el.remove();
            });
        }
    """


async def dismiss_ad_overlay(page, timeout: float = 20.0) -> bool:
    """Wait for the pre-init ad countdown to finish, then click the X.

    Called right after click_play opens the /play/ page. Watches for the
    overlay + countdown, then dismisses via .pre-init-ads--close.
    Returns True if dismissed, False if no overlay appeared or it got stuck.
    """
    print("    [ad] watching for ad overlay ...")
    deadline = time.time() + timeout
    saw_overlay = False
    last_cd = None

    while time.time() < deadline:
        # overlay present?
        try:
            if await page.locator(".player-pre-init-ads").count() > 0:
                saw_overlay = True
        except Exception:
            pass

        # live countdown value
        try:
            cd_el = page.locator(".player-pre-init-ads_timer__value").first
            if await cd_el.count() > 0:
                cd = (await cd_el.inner_text()).strip()
                if cd and cd != last_cd:
                    print(f"    [ad] countdown: {cd}")
                    last_cd = cd
        except Exception:
            pass

        # X visible? → dismiss
        try:
            close_btn = page.locator(".pre-init-ads--close").first
            if await close_btn.count() > 0 and await close_btn.is_visible():
                await close_btn.click(timeout=3000, force=True)
                print("    [ad] ✅ dismissed overlay via .pre-init-ads--close")
                return True
        except Exception:
            pass

        await page.wait_for_timeout(500)

    if saw_overlay:
        print(f"    [ad] ⚠️  overlay present but X never appeared "
              f"within {timeout:.0f}s")
    else:
        print(f"    [ad] no ad overlay appeared")
    return False


# ============================================================
# capture — TV show
# ============================================================
async def _dismiss_terabox_nuisances(page) -> int:
    """Close discount popup + Tera AI panel if present.

    These appear randomly on terabox.com and can block row clicks or
    the confirm dialog. Returns count of elements dismissed."""
    closed = 0
    sels = [
        ".new-coupon-popup .close-btn",
        ".coupon-Popup-box .close-btn",
        ".nd-agent-panel__close",
        ".nd-agent-panel .close",
        ".nd-agent-entry-wrap .icon-close",
    ]
    for sel in sels:
        try:
            loc = page.locator(sel)
            cnt = await loc.count()
        except Exception:
            continue
        for i in range(cnt):
            el = loc.nth(i)
            try:
                if not await el.is_visible():
                    continue
                await el.click(timeout=1500, force=True)
                closed += 1
                await page.wait_for_timeout(250)
            except Exception:
                continue
    return closed


async def _ad_present(page) -> bool:
    """Quick check: is a REAL pre-init ad overlay present right now?

    Ignores ghost overlays: after a successful dismiss the wrapper element
    sometimes lingers in the DOM with countdown '0' and no close button.
    Those count as 'not present' so we don't waste 12s on them."""
    try:
        wrapper = page.locator(".player-pre-init-ads").first
        if await wrapper.count() > 0:
            # real overlay has either a visible close X or countdown > 0
            try:
                close_x = page.locator(".pre-init-ads--close").first
                if await close_x.count() > 0 and await close_x.is_visible():
                    return True
            except Exception:
                pass
            try:
                cd = page.locator(".player-pre-init-ads_timer__value").first
                if await cd.count() > 0 and await cd.is_visible():
                    txt = ((await cd.inner_text()) or "").strip()
                    if txt.isdigit() and int(txt) > 0:
                        return True
            except Exception:
                pass
            # wrapper present but nothing to interact with → ghost
            return False
    except Exception:
        pass
    return False


async def _force_remove_overlays(page) -> None:
    """JS-level scrub of leftover ad DOM. Used after X is clicked, or when
    a ghost overlay is detected."""
    try:
        await page.evaluate(_strip_overlay_js())
    except Exception:
        pass
    try:
        await page.evaluate("""
            () => {
                document.querySelectorAll('.player-pre-init-ads')
                    .forEach(el => el.remove());
                document.querySelectorAll('.pre-init-ads--loading-please-wait')
                    .forEach(el => el.remove());
            }
        """)
    except Exception:
        pass


async def _close_popups_and_refocus(context, page) -> int:
    """Close every window/tab in this context EXCEPT page.

    IMPORTANT: only calls page.bring_to_front() if we actually closed
    something. bring_to_front fires focus/blur events that collapse
    dropdowns mid-interaction, so calling it when there are no popups
    to close does more harm than good.
    """
    closed = 0
    try:
        for other in list(context.pages):
            if other is page:
                continue
            try:
                await other.close()
                closed += 1
            except Exception:
                pass
    except Exception:
        pass
    if closed > 0:
        try:
            await page.bring_to_front()
        except Exception:
            pass
    return closed


async def _dismiss_ad_if_present(page, timeout: float = 15.0, appear_wait: float = 5.0) -> bool:
    """Wait up to `appear_wait` for an ad overlay to appear, then run
    the full dismiss loop if one shows. Fast no-op otherwise.

    The ad overlay loads a beat AFTER navigation/clicks, so a single
    instant check races it in and lets the ad block the switcher
    before we notice it. Waiting here catches that case cleanly.
    """
    appear_deadline = time.time() + appear_wait
    while time.time() < appear_deadline:
        if await _ad_present(page):
            break
        await page.wait_for_timeout(300)
    else:
        return False

    ok = await dismiss_ad_overlay(page, timeout=timeout)
    # If overlay still present (ghost or blocked), force-remove
    await page.wait_for_timeout(400)
    if await _ad_present(page):
        print("    [ad] overlay lingering — force-scrubbing DOM")
        await _force_remove_overlays(page)
        await page.wait_for_timeout(400)
    return ok


async def _find_live_switcher(page, cls_name: str):
    """Return the visible .<cls_name> div that is NOT inside .tw-main-modal.

    The /play/ page has two .seasons-switcher elements: one inside the
    hidden downloads modal, one live next to the player. We want the
    live one. Preferred by geometry (lower on page) after filtering
    out modal descendants.
    """
    try:
        candidates = page.locator(f".{cls_name}:visible")
        cnt = await candidates.count()
    except Exception:
        return None

    live = []
    for i in range(cnt):
        el = candidates.nth(i)
        try:
            in_modal = await el.evaluate(
                "el => !!el.closest('.tw-main-modal')"
            )
            if in_modal:
                continue
            box = await el.bounding_box()
            if box and box["width"] > 0:
                live.append((box["y"], el))
        except Exception:
            continue

    if not live:
        return None
    live.sort(key=lambda t: t[0], reverse=True)   # deepest y first
    return live[0][1]


async def _pick_from_switcher(page, switcher_cls: str, label: str,
                              target_num: int, context=None,
                              attempts: int = 3) -> bool:
    """Open a live switcher dropdown and click the option matching
    '<label> <N>'. label is 'Season' or 'Episode'.

    Retries up to `attempts` times — after each failure, closes any
    popup windows and refocuses the main page. Popup ads steal focus
    mid-flow; refocusing before the click is what makes this reliable.
    """
    for attempt in range(1, attempts + 1):
        # Settle buffer: the site fires an ad / popup ~right after
        # the previous interaction. Give it 8s to appear — popups are
        # silently eaten by the on_popup handler in capture_stream, so
        # no close + refocus here (that triggers focus-driven loops).
        await page.wait_for_timeout(8000)
        await page.wait_for_timeout(500)

        sw = await _find_live_switcher(page, switcher_cls)
        if sw is None:
            print(f"    [pick/{label}] no live .{switcher_cls} "
                  f"(attempt {attempt}/{attempts})")
            await page.wait_for_timeout(800)
            continue

        # real mouse click to open the dropdown
        try:
            box = await sw.bounding_box()
            if box:
                cx = box["x"] + box["width"] / 2
                cy = box["y"] + box["height"] / 2
                await page.mouse.move(cx, cy)
                await page.wait_for_timeout(120)
                await page.mouse.down()
                await page.wait_for_timeout(60)
                await page.mouse.up()
            else:
                await sw.click(timeout=5000, force=True)
        except Exception as e:
            print(f"    [pick/{label}] open failed: {e}")
            await page.wait_for_timeout(800)
            continue

        await page.wait_for_timeout(1200)

        # NOTE: do NOT call _close_popups_and_refocus here. Even with the
        # conditional bring_to_front fix, closing anything mid-dropdown
        # risks a focus event that collapses the menu. Let stray popups
        # sit until the next attempt's top-of-loop cleanup.

        # click the target option (dropdown entry appears as a plain span).
        # If the option isn't visible, the dropdown was probably closed by
        # a popup stealing focus mid-flight — re-open the switcher and
        # retry, up to 4 reopens per outer attempt.
        clicked = False
        for reopen_try in range(1, 5):
            for txt in (f"{label} {target_num}",
                        f"{label} {target_num:02d}"):
                # EXACT text match — quoted. Without quotes, "Season 1"
                # also matches "Season 10", "Season 19", etc.
                exact = f'"{txt}"'
                try:
                    loc = page.locator(f"text={exact}")
                    cnt = await loc.count()
                    if cnt > 0:
                        # prefer the FIRST match (topmost in the list)
                        await loc.first.click(timeout=4000, force=True)
                        print(f"    [pick/{label}] clicked {txt!r} "
                              f"(exact, {cnt} match(es), "
                              f"attempt {attempt}, reopen {reopen_try})")
                        await page.wait_for_timeout(1500)
                        clicked = True
                        break
                except Exception:
                    continue
            if clicked:
                return True

            # miss — re-open the switcher and try again
            print(f"    [pick/{label}] option not visible — "
                  f"re-opening dropdown (reopen {reopen_try}/4)")
            try:
                sw2 = await _find_live_switcher(page, switcher_cls)
                if sw2 is not None:
                    box2 = await sw2.bounding_box()
                    if box2:
                        cx2 = box2["x"] + box2["width"] / 2
                        cy2 = box2["y"] + box2["height"] / 2
                        await page.mouse.move(cx2, cy2)
                        await page.wait_for_timeout(120)
                        await page.mouse.down()
                        await page.wait_for_timeout(60)
                        await page.mouse.up()
                    else:
                        await sw2.click(timeout=4000, force=True)
                await page.wait_for_timeout(1000)
            except Exception:
                pass
            # NOTE: intentionally NO _close_popups_and_refocus here.
            # We just opened the dropdown with the switcher click above —
            # bringing the page to front or closing pages now would fire
            # a focus/blur event and collapse the menu before the next
            # option lookup. Top-of-attempt cleanup handles popups.

        print(f"    [pick/{label}] no option matching "
              f"{label} {target_num} after 4 reopens "
              f"(attempt {attempt}/{attempts})")
        await page.wait_for_timeout(800)

    return False


async def capture_stream(url, season, episode, wait_time, headless):
    """TV capture flow (matches the new site layout):

      1. Show page → click #shows-external-player-link
      2. Lands on /shows/play/<id>#S0-E20-... (site default)
      3. Dismiss the pre-init ad overlay
      4. Open the LIVE .seasons-switcher (outside .tw-main-modal)
         → click "Season <N>"
      5. Open the LIVE .episodes-switcher → click "Episode <M>"
      6. Dismiss ad again if it re-fires after picker interaction
      7. Wait for the stream URL that matches S<N>-E<M>
    """
    captured = []
    referer = url
    cookie_header = ""

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            user_agent=UA_CAPTURE,
            viewport={"width": 1366, "height": 900},
            locale="en-US",
        )
        await context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => undefined});"
        )
        page = await context.new_page()

        # Aggressively auto-close popup windows the instant they appear.
        # TeraBox ads and lookmovie2 popups steal focus and break picker
        # interactions if left open.
        # ── popup suppression (single source of truth) ─────────────
        # The site spawns ad popups on nearly every click AND on focus
        # events. Spamming bring_to_front() causes a focus → popup →
        # focus → popup loop. So we:
        #   1. queue popups as they appear
        #   2. close them all in one debounced drain
        #   3. refocus the main page ONCE per burst, only if we closed
        #      anything
        main_page = page
        popups: list = []
        _popup_drain_running = [False]

        async def _drain_popups():
            if _popup_drain_running[0]:
                return
            _popup_drain_running[0] = True
            try:
                # let a burst accumulate so we don't close 4 popups
                # one-at-a-time and trigger 4 refocus events
                await asyncio.sleep(0.15)
                closed_any = False
                while popups:
                    pg = popups.pop(0)
                    try:
                        if not pg.is_closed():
                            await pg.close()
                            closed_any = True
                    except Exception:
                        pass
                if closed_any:
                    try:
                        await main_page.bring_to_front()
                    except Exception:
                        pass
            finally:
                _popup_drain_running[0] = False

        def on_popup(pg):
            if pg is main_page:
                return
            popups.append(pg)
            try:
                asyncio.create_task(_drain_popups())
            except Exception:
                pass

        context.on("page", on_popup)

        def on_req(req):
            u = req.url
            if any(ext in u.lower() for ext in STREAM_EXTS) and u not in captured:
                captured.append(u)

        page.on("request", on_req)

        base_url = url.split("#", 1)[0]
        try:
            await page.goto(base_url, wait_until="domcontentloaded",
                            timeout=60000)
        except Exception as e:
            print(f"    [!] Navigation: {e}")
            await browser.close()
            return None, "", referer

        # 1) settle on show page
        await page.wait_for_timeout(10000)
        try:
            await page.evaluate(_strip_overlay_js())
        except Exception:
            pass
        await page.wait_for_timeout(500)

        # 2) click external player link → navigate to /play/
        print("    [nav] clicking #shows-external-player-link → /play/")
        try:
            await page.locator("#shows-external-player-link").first.click(
                timeout=8000, force=True)
        except Exception as e:
            print(f"    [nav] failed: {e}")
            await browser.close()
            return None, "", referer

        # 3) wait for /play/ URL
        for _ in range(20):
            await page.wait_for_timeout(1000)
            if "/play/" in page.url:
                break
        await page.wait_for_timeout(3000)
        print(f"    [nav] /play/ loaded: {page.url}")

        # 4) dismiss first ad overlay (waits up to 5s for it to appear)
        await _dismiss_ad_if_present(page, timeout=20.0)
        # settle buffer — the site fires late ads / bind delays here
        await page.wait_for_timeout(8000)

        # 4b) re-check for an ad that loaded AFTER the first window;
        #     if one is up now it is covering the switcher.
        await _dismiss_ad_if_present(page, timeout=15.0)
        await page.wait_for_timeout(500)

        # 5) pick season + episode on the live switchers.
        print(f"    [pick] selecting Season {season} Episode {episode}")

        picked_season = await _pick_from_switcher(
            page, "seasons-switcher", "Season", season, context=context)
        if not picked_season:
            print(f"    [!!] season pick failed")

        await _dismiss_ad_if_present(page, timeout=12.0)
        # settle buffer after mid-flow ad
        await page.wait_for_timeout(8000)
        await page.wait_for_timeout(500)

        picked_episode = await _pick_from_switcher(
            page, "episodes-switcher", "Episode", episode, context=context)
        if not picked_episode:
            print(f"    [!!] episode pick failed")

        await _dismiss_ad_if_present(page, timeout=12.0)
        # settle buffer after episode pick
        await page.wait_for_timeout(8000)
        await page.wait_for_timeout(500)

        # 6) wait for stream — prefer the one matching S{N}-E{M}
        pat = re.compile(rf"-s0*{season}-e0*{episode}(?:[-/._]|$)", re.I)
        deadline = time.time() + wait_time
        while time.time() < deadline:
            await page.wait_for_timeout(2000)
            if [u for u in captured if pat.search(u)]:
                await page.wait_for_timeout(3000)
                break

        if captured:
            cookies = await context.cookies()
            cookie_header = "; ".join(
                f"{c.get('name', '')}={c.get('value', '')}" for c in cookies
            )

        await browser.close()

    if not captured:
        return None, "", referer

    print(f"    [debug] captured {len(captured)} stream URL(s):")
    for u in captured:
        print(f"      • {u}")

    pat = re.compile(rf"-s0*{season}-e0*{episode}(?:[-/._]|$)", re.I)
    wanted = [u for u in captured if ".m3u8" in u and pat.search(u)]
    if not wanted:
        print(f"    [!!] no captured stream matches "
              f"S{season:02d}E{episode:02d}")
        return None, cookie_header, referer

    stream = wanted[-1]
    print(f"    [picked] {stream}")
    return stream, cookie_header, referer


# ============================================================
async def capture_movie_stream(url, wait_time, headless):
    captured = []
    referer = url
    cookie_header = ""

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            user_agent=UA_CAPTURE,
            viewport={"width": 1366, "height": 768},
            locale="en-US",
        )
        await context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        # Neutralize window.open so lookmovie2's popup ads can't spawn new
        # windows/tabs mid-click — nothing in the capture flow needs it.
        await context.add_init_script(
            """
            // Block every common popup vector:
            //   1. window.open
            //   2. synthetic anchor clicks with target=_blank
            //   3. click events on target=_blank anchors (capture phase)
            window.open = function(){ return null; };
            const _origAnchorClick = HTMLAnchorElement.prototype.click;
            HTMLAnchorElement.prototype.click = function() {
                const t = this.getAttribute('target');
                if (t === '_blank' || t === 'blank') {
                    console.warn('blocked anchor.click → target=_blank');
                    return;
                }
                return _origAnchorClick.apply(this, arguments);
            };
            document.addEventListener('click', function(e) {
                const a = e.target && e.target.closest
                    ? e.target.closest('a[target=_blank]') : null;
                if (a) {
                    console.warn('blocked click on target=_blank');
                    e.preventDefault();
                    e.stopImmediatePropagation();
                }
            }, true);
            """
        )
        page = await context.new_page()

        popups = []
        context.on("page", lambda pg: popups.append(pg))

        def close_popups():
            for pg in popups:
                try:
                    asyncio.create_task(pg.close())
                except Exception:
                    pass

        def on_req(req):
            u = req.url
            if any(ext in u.lower() for ext in STREAM_EXTS) and u not in captured:
                captured.append(u)

        page.on("request", on_req)

        base_url = url.split("#", 1)[0]
        try:
            await page.goto(base_url, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"    [!] Navigation: {e}")
            await browser.close()
            return None, "", referer

        await page.wait_for_timeout(15000)
        close_popups()
        try:
            await page.evaluate(_strip_overlay_js())
        except Exception:
            pass
        await page.wait_for_timeout(500)
        close_popups()

        for attempt in range(3):
            clicked = await click_play(page)
            if clicked:
                break
            await page.wait_for_timeout(3000)
            close_popups()

        # If the click opened /play/, an ad overlay may be up — dismiss it
        await page.wait_for_timeout(2500)
        close_popups()
        await dismiss_ad_overlay(page, timeout=15.0)
        close_popups()

        deadline = time.time() + wait_time
        while time.time() < deadline:
            await page.wait_for_timeout(2000)
            if captured:
                await page.wait_for_timeout(6000)
                break

        if not captured:
            await click_play(page)
            await page.wait_for_timeout(10000)

        if captured:
            cookies = await context.cookies()
            cookie_header = "; ".join(
                f"{c.get('name', '')}={c.get('value', '')}" for c in cookies
            )

        await browser.close()

    if not captured:
        return None, "", referer

    print(f"    [debug] captured {len(captured)} stream URL(s):")
    for u in captured:
        print(f"      • {u}")

    m3u8s = [u for u in captured if ".m3u8" in u]
    if not m3u8s:
        print(f"    [!!] no m3u8 captured")
        return None, cookie_header, referer

    stream = m3u8s[-1]
    print(f"    [picked] {stream}")
    return stream, cookie_header, referer


# ============================================================
# yt-dlp → RAM
# ============================================================
def stream_to_memory(stream_url, cookie_header, referer, tag, max_bytes):
    cookie_path = None
    if cookie_header:
        fd, cookie_path = tempfile.mkstemp(prefix="ytc_", suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("# Netscape HTTP Cookie File\n\n")
            for pair in cookie_header.split("; "):
                if "=" not in pair:
                    continue
                name, _, value = pair.partition("=")
                f.write(f".lookmovie2.to\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")
                f.write(f".pipect.site\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")
                f.write(f".myralink.site\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")
                f.write(f".housad.site\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")

    fd, tmp_video = tempfile.mkstemp(prefix="ee_tb_", suffix=".mp4")
    os.close(fd)

    cmd = [
        os.environ.get("YTDLP_PATH", "/Volumes/Backup_Plus/BROWSER_TEST/bin/yt-dlp"),
        "-o", tmp_video,
        "--no-part",
        "--no-warnings",
        "--quiet",
        "--concurrent-fragments", "4",
        "--retries", "20",
        "--fragment-retries", "20",
        "--retry-sleep", "fragment:3",
        "--referer", referer,
        "--user-agent", UA_CAPTURE,
    ]
    if cookie_path:
        cmd += ["--cookies", cookie_path]
    cmd.append(stream_url)

    print(f"    [*] downloading {tag} via yt-dlp → temp file ...")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        while proc.poll() is None:
            try:
                sz = os.path.getsize(tmp_video)
                print(f"\r      … {human_bytes(sz)}", end="", flush=True)
            except OSError:
                pass
            time.sleep(0.5)
        print()

        stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        rc = proc.returncode
        if rc != 0:
            raise RuntimeError(f"yt-dlp exit {rc}: {stderr.strip()[-600:]}")

        size = os.path.getsize(tmp_video)
        if size == 0:
            raise RuntimeError("yt-dlp produced a 0-byte file")

        print(f"    [*] reading {human_bytes(size)} into RAM ...")
        chunks: list[bytes] = []
        total = 0
        with open(tmp_video, "rb") as f:
            while True:
                data = f.read(CHUNK_SIZE)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if total > max_bytes:
                    raise RuntimeError(
                        f"exceeded RAM ceiling {human_bytes(max_bytes)}"
                    )
        print(f"    [✓] {human_bytes(total)} buffered ({len(chunks)} chunk(s))")
        return chunks, total
    finally:
        if cookie_path:
            try:
                os.unlink(cookie_path)
            except Exception:
                pass
        try:
            os.unlink(tmp_video)
        except Exception:
            pass


# ============================================================
# capture + encrypt composite (used by ghost mode)
# ============================================================
async def capture_and_encrypt_episode(url, show, season, episode,
                                     wait_time, headless, master, source_url):
    """Returns (ciphertext, orig_filename, mask) or (None, name, mask) on fail."""
    tag = f"S{season:02d}E{episode:02d}"
    orig_filename = f"{sanitize(show)} - {tag}.mp4"
    mask = mask_name(master, show, season, episode)

    print(f"\n{'=' * 62}\n  {tag}\n{'=' * 62}")
    print("  [*] capturing...")
    stream, cookie_header, referer = await capture_stream(
        url, season, episode, wait_time, headless
    )
    if not stream:
        print(f"  [fail] no stream")
        return None, orig_filename, mask
    print(f"  [+] {stream}")

    try:
        chunks, size = stream_to_memory(
            stream, cookie_header, referer, tag, MAX_RAM_BYTES_ENCRYPT
        )
    except Exception as e:
        print(f"  [fail] streaming: {e}")
        return None, orig_filename, mask

    print(f"    [*] encrypting {human_bytes(size)} with AES-256-GCM ...")
    metadata = {
        "v": 1, "type": "episode", "orig_name": orig_filename,
        "show": show, "season": int(season), "episode": int(episode),
        "size": int(size), "created": iso_now(), "source": source_url,
    }
    try:
        ciphertext = encrypt_blob(chunks, metadata, master)
    except Exception as e:
        chunks.clear()
        print(f"  [fail] encryption: {e}")
        return None, orig_filename, mask

    print(f"    [✓] encrypted → {human_bytes(len(ciphertext))} "
          f"(+{len(ciphertext) - size} bytes overhead)")
    return ciphertext, orig_filename, mask


async def capture_and_encrypt_movie(url, title, year,
                                    wait_time, headless, master):
    tag = sanitize(title)
    if year:
        tag = f"{tag}_{year}"
    orig_filename = f"{tag}.mp4"
    mask = mask_name_movie(master, title, year)

    print(f"\n{'=' * 62}\n  {tag}\n{'=' * 62}")
    print("  [*] capturing...")
    stream, cookie_header, referer = await capture_movie_stream(
        url, wait_time, headless
    )
    if not stream:
        print(f"  [fail] no stream")
        return None, orig_filename, mask
    print(f"  [+] {stream}")

    try:
        chunks, size = stream_to_memory(
            stream, cookie_header, referer, tag, MAX_RAM_BYTES_ENCRYPT
        )
    except Exception as e:
        print(f"  [fail] streaming: {e}")
        return None, orig_filename, mask

    print(f"    [*] encrypting {human_bytes(size)} with AES-256-GCM ...")
    metadata = {
        "v": 1, "type": "movie", "orig_name": orig_filename,
        "title": title, "year": year,
        "size": int(size), "created": iso_now(), "source": url,
    }
    try:
        ciphertext = encrypt_blob(chunks, metadata, master)
    except Exception as e:
        chunks.clear()
        print(f"  [fail] encryption: {e}")
        return None, orig_filename, mask

    print(f"    [✓] encrypted → {human_bytes(len(ciphertext))} "
          f"(+{len(ciphertext) - size} bytes overhead)")
    return ciphertext, orig_filename, mask


# ============================================================
# TeraBox sniff / login
# ============================================================
def try_extract_tokens(text):
    if not text:
        return
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if data:
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if (
                        k in TOKEN_KEYS
                        and isinstance(v, str)
                        and v
                        and k not in sniffed_tokens
                    ):
                        sniffed_tokens[k] = v
                        print(f"  🔑 Sniffed {k} = {v[:40]}...")
                    stack.append(v)
            elif isinstance(node, list):
                stack.extend(node)
    else:
        for key in TOKEN_KEYS:
            m = re.search(rf"{key}=([^&\s\"']+)", text)
            if m and key not in sniffed_tokens:
                sniffed_tokens[key] = m.group(1)
                print(f"  🔑 Sniffed {key} = {m.group(1)[:40]}...")


async def handle_response(response):
    url = response.url
    if any(x in url for x in ["google", "facebook", "stripe", "analytics"]):
        return
    if any(
        x in url
        for x in ["api/list", "api/home", "api/precreate", "api/upload", "api/create"]
    ):
        try_extract_tokens(url)
    ctype = response.headers.get("content-type", "")
    if "json" in ctype or "javascript" in ctype:
        try:
            try_extract_tokens(await response.text())
        except Exception:
            pass


async def is_logged_in(context):
    return any(c.get("name") == "ndus" for c in await context.cookies())


async def do_login(page, context):
    if not TERABOX_USERNAME or not TERABOX_PASSWORD:
        print("  ⚠️  no credentials loaded for active account — check .env")
        return False

    login_urls = [f"{WEB_HOST}/login", f"{WEB_HOST}/passport/login"]

    for url in login_urls:
        print(f"[*] Navigating to {url} ...")
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"  ⚠️  nav failed: {e}")
            continue
        await page.wait_for_timeout(3000)

        try:
            print(f"  page: {page.url}  |  title: {await page.title()}")
        except Exception:
            pass

        if await is_logged_in(context):
            print("  ✅ already logged in (ndus present after nav)")
            return True

        for sel in PASSWORD_TAB_SELECTORS:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await loc.is_visible():
                    await loc.click(timeout=2000)
                    print(f"  → clicked password tab: {sel}")
                    await page.wait_for_timeout(1000)
                    break
            except Exception:
                continue

        filled_user = False
        for sel in USERNAME_SELECTORS:
            try:
                loc = page.locator(sel).first
                cnt = await loc.count()
                if cnt > 0 and await loc.is_visible():
                    await loc.click(timeout=2000)
                    await loc.fill("")
                    await loc.type(TERABOX_USERNAME, delay=20)
                    filled_user = True
                    print(f"  ✓ username filled (via {sel})")
                    break
            except Exception:
                continue

        if not filled_user:
            print(f"  ⚠️  no username field matched — dumping <input> list:")
            try:
                inputs = await page.query_selector_all("input")
                print(f"    {len(inputs)} <input> element(s) on page:")
                for i, inp in enumerate(inputs):
                    try:
                        name = await inp.get_attribute("name") or "?"
                        typ = await inp.get_attribute("type") or "?"
                        ph = (await inp.get_attribute("placeholder") or "?")[:40]
                        vis = await inp.is_visible()
                        print(f"      [{i}] name={name!r} type={typ!r} "
                              f"ph={ph!r} vis={vis}")
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                btns = await page.query_selector_all("button")
                print(f"    {len(btns)} <button> element(s) on page:")
                for i, b in enumerate(btns[:10]):
                    try:
                        txt = (await b.inner_text())[:40]
                        vis = await b.is_visible()
                        print(f"      [{i}] text={txt!r} vis={vis}")
                    except Exception:
                        pass
            except Exception:
                pass
            continue

        filled_pw = False
        for sel in PASSWORD_SELECTORS:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await loc.is_visible():
                    await loc.click(timeout=2000)
                    await loc.fill("")
                    await loc.type(TERABOX_PASSWORD, delay=20)
                    filled_pw = True
                    print(f"  ✓ password filled")
                    break
            except Exception:
                continue
        if not filled_pw:
            print("  ⚠️  password field not found")
            continue

        submitted = False
        for sel in SUBMIT_SELECTORS:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await loc.is_visible():
                    await loc.click(timeout=3000)
                    submitted = True
                    print(f"  ✓ submit clicked (via {sel})")
                    break
            except Exception:
                continue
        if not submitted:
            try:
                await page.keyboard.press("Enter")
                print("  ✓ submit via Enter")
            except Exception:
                pass

        print("  ⏳ waiting for login (solve captcha if needed) ...")
        for _ in range(120):
            await page.wait_for_timeout(500)
            if await is_logged_in(context):
                print("  ✅ logged in (ndus present)")
                return True
        print("  ⚠️  not logged in after 60s on this URL")

    return await is_logged_in(context)


async def force_jsToken(page):
    print("  [*] triggering /api/list to capture jsToken ...")
    try:
        result = await page.evaluate(
            """
            async () => {
                try {
                    const r = await fetch(
                        '/api/list?dir=%2F&order=time&desc=1'
                        + '&showempty=0&page=1&num=1',
                        {
                            credentials: 'include',
                            headers: {'X-Requested-With': 'XMLHttpRequest'}
                        }
                    );
                    const txt = await r.text();
                    return txt.slice(0, 300);
                } catch (e) {
                    return 'ERR:' + String(e);
                }
            }
            """
        )
        if isinstance(result, str) and result.startswith("ERR:"):
            print(f"  ⚠️  fetch failed: {result}")
            return False
        print(f"  [*] /api/list responded ({len(result)} chars)")
        return True
    except Exception as e:
        print(f"  ⚠️  force_jsToken raised: {e}")
        return False


async def is_really_logged_in(page) -> bool:
    try:
        if await page.locator('input[type="password"]').count() > 0:
            return False
    except Exception:
        pass
    url = page.url.lower()
    if any(x in url for x in ["/login", "/passport", "signin", "sign-in"]):
        return False
    try:
        has_main = await page.locator('text=My Files').count() > 0
        has_avatar = await page.locator('[class*="avatar"]').count() > 0
        if has_main or has_avatar:
            return True
    except Exception:
        pass
    return True


async def wait_for_manual_login(page, context):
    print()
    print("=" * 62)
    print(f"  MANUAL LOGIN NEEDED  (account {ACTIVE_ACCOUNT})")
    print("=" * 62)
    print("  1. In the Chrome window, log in to TeraBox.")
    print("  2. Wait until you see the My Files / home page.")
    print("  3. Come back to THIS terminal and press Enter.")
    print("=" * 62)
    try:
        input("  press Enter when logged in: ")
    except (KeyboardInterrupt, EOFError):
        raise KeyboardInterrupt()

    try:
        await page.goto(f"{WEB_HOST}/main", wait_until="domcontentloaded")
        await page.wait_for_timeout(2500)
    except Exception:
        pass
    if await is_really_logged_in(page):
        print("  ✅ manual login confirmed")
        return True
    print("  ⚠️  still not logged in — continuing anyway (best effort)")
    return False


async def extract_tokens_from_page(page) -> dict:
    """Pull jsToken + bdstoken from localStorage / window / HTML.

    Returns a dict like {'jsToken': '...', 'bdstoken': '...'} — only
    includes tokens actually found. Values are chosen from keys whose
    NAME contains the token name (case-insensitive), so a generic hex
    localStorage entry won't be mistaken for the wrong token.
    """
    print("  [*] extracting tokens from page state ...")
    try:
        result = await page.evaluate(
            r"""
            () => {
                const out = {};
                const names = ['jsToken', 'bdstoken'];
                try {
                    for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        const v = localStorage.getItem(k);
                        if (!k) continue;
                        for (const n of names) {
                            if (new RegExp(n, 'i').test(k)) {
                                out['ls:' + n + ':' + k] = v;
                            }
                        }
                        if (v && /^[A-Fa-f0-9]{20,}$/.test(v)) {
                            out['hex:' + k] = v;
                        }
                    }
                } catch(e) {}
                try { if (window.jsToken) out['window:jsToken'] = window.jsToken; } catch(e) {}
                try { if (window.__jsToken) out['window:__jsToken'] = window.__jsToken; } catch(e) {}
                try { if (window.bdstoken) out['window:bdstoken'] = window.bdstoken; } catch(e) {}
                try { if (window.__bdstoken) out['window:__bdstoken'] = window.__bdstoken; } catch(e) {}
                try {
                    const html = document.documentElement.outerHTML;
                    let m = html.match(/jsToken\s*[=:]\s*["']([A-Fa-f0-9]{20,})["']/);
                    if (m) out['html:jsToken'] = m[1];
                    m = html.match(/bdstoken\s*[=:]\s*["']([A-Fa-f0-9]{20,})["']/);
                    if (m) out['html:bdstoken'] = m[1];
                } catch(e) {}
                return out;
            }
            """
        )
    except Exception as e:
        print(f"  ⚠️  extraction failed: {e}")
        return {}

    if not isinstance(result, dict) or not result:
        print("  [debug] nothing found in page state")
        return {}

    print(f"  [debug] {len(result)} candidate(s) found in page state:")
    for k, v in result.items():
        sval = str(v) if v is not None else ""
        print(f"      {k} = {sval[:50]}")

    found = {}
    for k, v in result.items():
        sval = str(v) if v is not None else ""
        if not (20 <= len(sval) <= 200):
            continue
        kl = k.lower()
        if "jstoken" in kl and "jsToken" not in found:
            found["jsToken"] = sval
        elif "bdstoken" in kl and "bdstoken" not in found:
            found["bdstoken"] = sval

    return found


# ============================================================
# cookie self-healing (per-account)
# ============================================================
def save_fresh_cookie_to_env(new_ndus: str, backup: bool = True) -> bool:
    new_ndus = new_ndus.strip()
    if not new_ndus:
        return False

    n = ACTIVE_ACCOUNT
    primary_key = f"TERABOX_{n}_COOKIE"
    legacy_keys = {"COOKIE_JSON", "NDUS"} if n == 1 else set()

    try:
        if not ENV_PATH.exists():
            print(f"  ⚠️  .env not found at {_redact_path(ENV_PATH)}")
            #print(f"  ⚠️  .env not found at {ENV_PATH}")
            return False

        lines = ENV_PATH.read_text().splitlines()

        if backup:
            try:
                (ENV_PATH.parent / ".env.bak").write_text(
                    "\n".join(lines) + "\n"
                )
            except Exception:
                pass

        history: list[str] = []
        others: list[str] = []
        key_re = re.compile(r"([A-Za-z0-9_]+)\s*=")

        for ln in lines:
            stripped = ln.lstrip()
            active = stripped.lstrip("#")
            m = key_re.match(active)
            key = m.group(1) if m else ""
            is_this_cookie = (key == primary_key) or (key in legacy_keys)
            if is_this_cookie:
                history.append(ln if stripped.startswith("#") else "#" + ln)
            else:
                others.append(ln)

        if len(history) > MAX_COOKIE_HISTORY:
            dropped = len(history) - MAX_COOKIE_HISTORY
            history = history[-MAX_COOKIE_HISTORY:]
            print(f"  [i] trimmed {dropped} old cookie line(s) for "
                  f"account {n} from history")

        out = others + history + [f"{primary_key}={new_ndus}"]
        ENV_PATH.write_text("\n".join(out) + "\n")
        return True
    except Exception as e:
        print(f"  ⚠️  could not write .env: {e}")
        return False


def load_auth_cookies_from_env() -> dict:
    n = ACTIVE_ACCOUNT
    raw = _read_env_value(f"TERABOX_{n}_COOKIE")
    if not raw and n == 1:
        raw = _read_env_value("COOKIE_JSON") or _read_env_value("NDUS")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return {k: str(v) for k, v in data.items()}
    except json.JSONDecodeError:
        pass
    return {"ndus": raw}


async def persist_fresh_cookie(context) -> None:
    try:
        cookies = await context.cookies()
        ndus = ""
        for c in cookies:
            if c.get("name") == "ndus" and c.get("domain", "").startswith("."):
                ndus = c.get("value", "")
                break
        if not ndus:
            for c in cookies:
                if c.get("name") == "ndus":
                    ndus = c.get("value", "")
                    break

        if not ndus:
            print("  [i] no ndus cookie in context — nothing to persist")
            return

        current = load_auth_cookies_from_env().get("ndus", "")
        if current == ndus:
            print(f"  [i] .env cookie (account {ACTIVE_ACCOUNT}) is already up-to-date")
            return

        if save_fresh_cookie_to_env(ndus):
            print(f"  ✅ .env updated: rotated ndus for account "
                  f"{ACTIVE_ACCOUNT} ({len(ndus)} chars)")
            print(f"     backup saved at {_redact_path(ENV_PATH)}.bak")
            #print(f"     backup saved at {ENV_PATH.parent / '.env.bak'}")
        else:
            print("  ⚠️  could not update .env")
    except Exception as e:
        print(f"  ⚠️  persist_fresh_cookie raised: {e}")


def _terabox_sniff_http_sync(account_n: int):
    """Pure-HTTP sniff. Returns (cookie_header, tokens) or raises RuntimeError."""
    import requests as _req

    raw = _read_env_value(f"TERABOX_{account_n}_COOKIE")
    if not raw and account_n == 1:
        raw = _read_env_value("COOKIE_JSON") or _read_env_value("NDUS")
    if not raw:
        raise RuntimeError(f"no cookie in .env for account {account_n}")

    ndus = raw
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
            ndus = d.get("ndus", "")
        except Exception:
            pass
    if not ndus:
        raise RuntimeError(f"no ndus value for account {account_n}")

    sess = _req.Session()
    sess.headers.update({
        "User-Agent": UA_UPLOAD,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    sess.cookies.set("ndus", ndus, domain=".terabox.com")

    r = sess.get(f"{WEB_HOST}/main", timeout=30, allow_redirects=True)
    if r.status_code != 200:
        raise RuntimeError(f"/main returned {r.status_code}")

    html = r.text
    js_token = ""
    bd_token = ""

    m = re.search(r'"jsToken":"([^"]+)"', html)
    if m:
        decoded = unquote(m.group(1))
        m2 = re.search(r'fn\("([A-Fa-f0-9]+)"\)', decoded)
        if m2:
            js_token = m2.group(1)

    m = re.search(r'"bdstoken":"([A-Fa-f0-9]+)"', html)
    if m:
        bd_token = m.group(1)

    if not js_token:
        m = re.search(r'fn%28%22([A-Fa-f0-9]{30,})%22%29', html)
        if m:
            js_token = m.group(1)

    if not js_token:
        raise RuntimeError("could not extract jsToken from /main HTML")

    tokens = {"jsToken": js_token, "app_id": APP_ID}
    if bd_token:
        tokens["bdstoken"] = bd_token

    cookie_pairs = [f"{c.name}={c.value}" for c in sess.cookies]
    cookie_header = "; ".join(cookie_pairs)
    return cookie_header, tokens


async def terabox_sniff_http():
    """Async wrapper around the sync HTTP sniff."""
    global sniffed_tokens
    sniffed_tokens = {}

    print(f"\n[*] sniffing account {ACTIVE_ACCOUNT} via HTTP "
          f"(no browser) ...")

    auth_cookies = load_auth_cookies_from_env()
    if auth_cookies:
        print(f"  🔑 {len(auth_cookies)} auth cookie(s) in .env: "
              f"{list(auth_cookies.keys())}")

    cookie_header, tokens = await asyncio.to_thread(
        _terabox_sniff_http_sync, ACTIVE_ACCOUNT
    )

    sniffed_tokens = tokens
    print(f"  ✅ jsToken:  {tokens['jsToken'][:40]}... "
          f"({len(tokens['jsToken'])} chars)")
    if "bdstoken" in tokens:
        print(f"  ✅ bdstoken: {tokens['bdstoken'][:40]}... "
              f"({len(tokens['bdstoken'])} chars)")
    print(f"  🍪 cookie header: {len(cookie_header)} chars")

    return cookie_header, sniffed_tokens


async def terabox_sniff():
    """Try HTTP first, fall back to browser sniff on any failure."""
    try:
        return await terabox_sniff_http()
    except Exception as e:
        print(f"  [i] HTTP sniff failed ({type(e).__name__}: {e})")
        print(f"  [i] falling back to browser sniff ...")
    return await terabox_sniff_browser()


async def terabox_sniff_browser():
    global sniffed_tokens
    sniffed_tokens = {}
    cookie_header = ""

    print(f"\n[*] launching Chrome for TeraBox login/sniff "
          f"(account {ACTIVE_ACCOUNT})...")

    auth_cookies = load_auth_cookies_from_env()
    if auth_cookies:
        print(f"  🔑 {len(auth_cookies)} auth cookie(s) in .env: "
              f"{list(auth_cookies.keys())}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=os.getenv("PIPELINE_HEADLESS_SNIFF", "0") == "1")
        context = await browser.new_context(user_agent=UA_UPLOAD)

        if auth_cookies:
            n = await inject_auth_cookies(context, auth_cookies)
            print(f"  ✅ injected {n} cookie(s) into fresh context")

        page = await context.new_page()
        page.on("response", handle_response)

        print("[*] loading /main ...")
        try:
            await page.goto(f"{WEB_HOST}/main",
                            wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"  ⚠️  nav: {e}")
        await page.wait_for_timeout(4000)

        if await is_really_logged_in(page):
            print("  ✅ logged in (page shows home / no login form)")
        else:
            print("  ⚠️  not logged in — attempting form login")
            await do_login(page, context)
            try:
                await page.goto(f"{WEB_HOST}/main",
                                wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(3000)
            except Exception:
                pass
            if not await is_really_logged_in(page):
                await wait_for_manual_login(page, context)

        await persist_fresh_cookie(context)
        n_closed = await _dismiss_terabox_nuisances(page)
        if n_closed:
            print(f"  [i] dismissed {n_closed} nuisance popup(s)")

        sniffed_tokens.setdefault("app_id", APP_ID)

        if "jsToken" not in sniffed_tokens:
            print("  [*] waiting up to 8s for site JS to fire /api/list ...")
            for _ in range(16):
                await page.wait_for_timeout(500)
                if "jsToken" in sniffed_tokens:
                    break

        if "jsToken" not in sniffed_tokens or "bdstoken" not in sniffed_tokens:
            found = await extract_tokens_from_page(page)
            for key, val in found.items():
                if key not in sniffed_tokens:
                    sniffed_tokens[key] = val
                    print(f"  ✅ {key} extracted from page = {val[:40]}...")

        if "jsToken" not in sniffed_tokens:
            print("  [*] navigating to /disk/home to trigger SPA ...")
            try:
                await page.goto(f"{WEB_HOST}/disk/home",
                                wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass
            for _ in range(20):
                await page.wait_for_timeout(500)
                if "jsToken" in sniffed_tokens:
                    break

        if "jsToken" not in sniffed_tokens or "bdstoken" not in sniffed_tokens:
            found = await extract_tokens_from_page(page)
            for key, val in found.items():
                if key not in sniffed_tokens:
                    sniffed_tokens[key] = val
                    print(f"  ✅ {key} extracted after /disk/home = {val[:40]}...")

        if "jsToken" not in sniffed_tokens:
            await force_jsToken(page)
            await page.wait_for_timeout(1500)

        if "jsToken" in sniffed_tokens and "app_id" in sniffed_tokens:
            print("  ✅ jsToken captured automatically — no manual click needed")
            print("  ⚡ auto-proceeding in 1.5s (no Enter required)")
            await page.wait_for_timeout(1500)
        else:
            print(
                """
  ⚠️  jsToken not captured automatically.
  Click any folder in the TeraBox window, then press Enter.
"""
            )

            print()
            print("  press Enter here once jsToken is captured "
                  "(or to continue anyway):")

            stop = threading.Event()

            def _wait():
                try:
                    input()
                except EOFError:
                    pass
                stop.set()

            threading.Thread(target=_wait, daemon=True).start()

            loop = asyncio.get_running_loop()
            start = loop.time()
            announced = nudged = False
            while not stop.is_set() and loop.time() - start < 300:
                if (
                    not announced
                    and "jsToken" in sniffed_tokens
                    and "app_id" in sniffed_tokens
                ):
                    print("  ✅ got jsToken + app_id — you can press Enter now.")
                    announced = True
                if (
                    not nudged
                    and loop.time() - start > 15
                    and "jsToken" not in sniffed_tokens
                ):
                    print("  ⏳ still waiting — click a folder in the TeraBox window")
                    nudged = True
                await page.wait_for_timeout(500)

        cookies = await context.cookies()
        cookie_header = "; ".join(
            f"{c.get('name', '')}={c.get('value', '')}" for c in cookies
        )
        print(f"\n🍪 cookies: {len(cookie_header)} chars (memory only)")
        await browser.close()

    return cookie_header, sniffed_tokens


# ============================================================
# TeraBox API client
# ============================================================
class TeraBoxUploader:
    def __init__(self, cookie_header, tokens):
        self.tokens = tokens
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": UA_UPLOAD,
                "Referer": WEB_HOST + "/disk/home",
                "Origin": WEB_HOST,
                "Cookie": cookie_header,
                "X-Requested-With": "XMLHttpRequest",
            }
        )

    def _request(self, method, url, *, retries=5, **kw):
        last = None
        for attempt in range(1, retries + 1):
            try:
                r = self.session.request(method, url, **kw)
                r.raise_for_status()
                return r
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ChunkedEncodingError,
            ) as e:
                last = e
                if attempt == retries:
                    raise
                wait = min(2 ** attempt, 15)
                print(
                    f"     ⚠️  {type(e).__name__} (attempt {attempt}/{retries})"
                    f" — retrying in {wait}s"
                )
                time.sleep(wait)
            except requests.exceptions.HTTPError as e:
                code = e.response.status_code if e.response is not None else 0
                if 500 <= code < 600 and attempt < retries:
                    wait = min(2 ** attempt, 15)
                    print(
                        f"     ⚠️  HTTP {code} (attempt {attempt}/{retries})"
                        f" — retrying in {wait}s"
                    )
                    time.sleep(wait)
                    continue
                raise
        raise RuntimeError("all retries exhausted without an exception")

    def _params(self, extra=None):
        p = {
            "app_id": APP_ID,
            "channel": CHANNEL,
            "clienttype": CLIENTTYPE,
            "web": WEB,
            "bdstoken": self.tokens.get("bdstoken", ""),
            "jsToken": self.tokens.get("jsToken", ""),
        }
        if extra:
            p.update(extra)
        return {k: v for k, v in p.items() if v}

    def list_dir(self, remote_dir="/"):
        r = self._request(
            "GET",
            f"{WEB_HOST}/api/list",
            params=self._params(
                {
                    "dir": remote_dir,
                    "order": "time",
                    "desc": "1",
                    "showempty": "0",
                    "page": "1",
                    "num": "200",
                }
            ),
            timeout=30,
        )
        return r.json()

    def create_folder(self, parent, name):
        path = parent.rstrip("/") + "/" + name
        data = {
            "path": path,
            "isdir": "1",
            "block_list": "[]",
            "size": "0",
            "rtype": "1",
        }
        r = self._request(
            "POST",
            f"{WEB_HOST}/api/create",
            params=self._params(data),
            data=data,
            timeout=30,
        )
        return r.json()

    def precreate(self, remote_dir, filename, size, block_list):
        full_path = remote_dir.rstrip("/") + "/" + filename
        params = self._params()
        data = {
            "path": full_path,
            "autoinit": "1",
            "target_path": remote_dir.rstrip("/") or "/",
            "block_list": json.dumps(block_list),
            "local_mtime": str(int(time.time())),
            "size": str(size),
        }
        r = self._request(
            "POST",
            f"{WEB_HOST}/api/precreate",
            params=params,
            data=data,
            timeout=120,
            retries=6,
        )
        return r.json()

    def rapid_upload(self, remote_dir, filename, size, content_md5_hex, slice_md5):
        full_path = remote_dir.rstrip("/") + "/" + filename
        params = self._params()
        data = {
            "path": full_path,
            "content-length": str(size),
            "content-md5": content_md5_hex,
            "slice-md5": slice_md5,
            "block_list": json.dumps([content_md5_hex]),
            "target_path": remote_dir.rstrip("/") or "/",
        }
        r = self._request(
            "POST",
            f"{WEB_HOST}/api/rapidupload",
            params=params,
            data=data,
            timeout=60,
            retries=4,
        )
        return r.json()

    def upload_chunk(self, full_path, uploadid, chunk, partseq):
        params = {
            "method": "upload",
            "app_id": APP_ID,
            "channel": CHANNEL,
            "clienttype": CLIENTTYPE,
            "web": WEB,
            "path": full_path,
            "uploadid": uploadid,
            "uploadsign": "0",
            "partseq": str(partseq),
        }
        r = self._request(
            "POST",
            f"{UPLOAD_HOST}/rest/2.0/pcs/superfile2",
            params=params,
            files={"file": ("blob", chunk, "application/octet-stream")},
            timeout=240,
            retries=5,
        )
        return r.json()

    def create_file(self, remote_dir, filename, size, uploadid, block_list):
        full_path = remote_dir.rstrip("/") + "/" + filename
        params = self._params()
        data = {
            "path": full_path,
            "size": str(size),
            "isdir": "0",
            "rtype": "1",
            "block_list": json.dumps(block_list),
            "uploadid": uploadid,
            "target_path": remote_dir.rstrip("/") or "/",
        }
        r = self._request(
            "POST",
            f"{WEB_HOST}/api/create",
            params=params,
            data=data,
            timeout=120,
            retries=6,
        )
        return r.json()

    def delete_remote_file(self, remote_dir, filename):
        full_path = remote_dir.rstrip("/") + "/" + filename
        url = f"{WEB_HOST}/api/filemanager"
        params = self._params({"opera": "delete", "async": "2", "onnest": "fail"})
        data = {"filelist": json.dumps([full_path])}
        try:
            r = self._request(
                "POST", url, params=params, data=data, timeout=30, retries=3
            )
            j = r.json()
            if j.get("errno") == 0:
                return True, j
            return False, j
        except Exception as e:
            return False, {"error": str(e)}

    def delete_remote_folder(self, remote_dir):
        """Delete a folder (and everything inside it) in one API call."""
        folder_path = remote_dir.rstrip("/")
        if not folder_path or folder_path == "/":
            return False, {"error": "refusing to delete root"}
        url = f"{WEB_HOST}/api/filemanager"
        params = self._params({"opera": "delete", "async": "2", "onnest": "fail"})
        data = {"filelist": json.dumps([folder_path])}
        try:
            r = self._request(
                "POST", url, params=params, data=data, timeout=30, retries=3
            )
            j = r.json()
            if j.get("errno") == 0:
                return True, j
            return False, j
        except Exception as e:
            return False, {"error": str(e)}

    def upload_from_memory(
        self, filename, chunks, size, remote_dir="/", skip_rapid=False
    ):
        num_chunks = len(chunks)
        full_path = remote_dir.rstrip("/") + "/" + filename
        print(f"\n📤 uploading: {filename} ({human_bytes(size)})")
        print(f"   → {full_path}")

        local_hex = [hashlib.md5(c).hexdigest() for c in chunks]
        h = hashlib.md5()
        for c in chunks:
            h.update(c)
        full_md5_hex = h.hexdigest()

        hs = hashlib.md5()
        need = 256 * 1024
        for c in chunks:
            if need <= 0:
                break
            take = c[:need]
            hs.update(take)
            need -= len(take)
        slice_md5 = base64.b64encode(hs.digest()).decode()

        print(f"   {num_chunks} chunk(s) | md5: {full_md5_hex[:16]}...")

        if not skip_rapid:
            try:
                rapid = self.rapid_upload(
                    remote_dir, filename, size, full_md5_hex, slice_md5
                )
                if rapid.get("errno") == 0:
                    fs_id = rapid.get("info", {}).get("fs_id")
                    print(f"   ✅ rapid upload! fs_id={fs_id}")
                    return rapid
                print(f"   rapid unavailable (errno={rapid.get('errno')}), chunking")
            except Exception as e:
                print(f"   rapid error: {e} — chunking")

        pre = self.precreate(remote_dir, filename, size, local_hex)
        if pre.get("errno") != 0:
            raise RuntimeError(f"precreate failed: {pre}")
        uploadid = pre.get("uploadid")
        if not uploadid:
            raise RuntimeError(f"no uploadid: {pre}")

        print(f"   uploading {num_chunks} chunk(s)...")
        server_md5s = []
        for i in range(num_chunks):
            for attempt in range(1, UPLOAD_MAX_RETRIES + 1):
                try:
                    resp = self.upload_chunk(full_path, uploadid, chunks[i], i)
                    if resp.get("errno") is None or resp.get("errno") == 0:
                        server_md5s.append(resp.get("md5") or local_hex[i])
                        pct = (i + 1) / num_chunks * 100
                        print(
                            f"\r     chunk {i + 1}/{num_chunks} ({pct:.1f}%)",
                            end="",
                            flush=True,
                        )
                        break
                    raise RuntimeError(f"chunk errno={resp.get('errno')}")
                except Exception as e:
                    if attempt == UPLOAD_MAX_RETRIES:
                        raise
                    print(
                        f"\n     retry {attempt}/{UPLOAD_MAX_RETRIES} chunk {i}: {e}"
                    )
                    time.sleep(UPLOAD_RETRY_DELAY)
        print()

        try:
            result = self.create_file(
                remote_dir, filename, size, uploadid, server_md5s
            )
        except Exception as e:
            print(f"   ⚠️  finalize failed: {type(e).__name__}: {e}")
            print(f"   [?] checking if file landed anyway ...")
            time.sleep(3)
            if remote_file_exists(self, remote_dir, filename, size=size):
                print(f"   ✅ file is present on TeraBox — treating as success")
                return {"errno": 0, "recovered": True}
            raise

        if result.get("errno") == 0:
            info = result.get("info")
            if isinstance(info, list) and info:
                fs_id = info[0].get("fs_id", "?")
            elif isinstance(info, dict):
                fs_id = info.get("fs_id", "?")
            else:
                fs_id = result.get("fs_id", "?")
            print(f"   ✅ uploaded! fs_id={fs_id}")
        else:
            print(f"   ⚠️  create errno={result.get('errno')}: {result}")
        return result


# ============================================================
# remote path helpers
# ============================================================
def remote_path_exists(uploader, path):
    try:
        return uploader.list_dir(path).get("errno") == 0
    except Exception:
        return False


def ensure_remote_path(uploader, path):
    path = "/" + path.strip("/")
    if path == "/":
        return "/"
    parts = [p for p in path.split("/") if p]
    current = ""
    for part in parts:
        current = current + "/" + part
        if remote_path_exists(uploader, current):
            print(f"  ✓ exists: {current}")
            continue
        parent = "/".join(current.split("/")[:-1]) or "/"
        print(f"  + create: {current}")
        try:
            r = uploader.create_folder(parent, part)
            if r.get("errno") != 0:
                print(f"  ⚠️  errno={r.get('errno')}: {r}")
                return "/"
        except Exception as e:
            print(f"  ⚠️  {e}")
            return "/"
    return current


def remote_file_exists(uploader, remote_dir, filename, size=None):
    try:
        r = uploader.list_dir(remote_dir)
        if r.get("errno") != 0:
            return False
        for it in r.get("list", []):
            if it.get("server_filename") == filename:
                if size is None:
                    return True
                try:
                    return int(it.get("size", 0)) == size
                except Exception:
                    return True
    except Exception:
        return False
    return False


def pick_remote_folder(uploader, suggested=""):
    env_override = os.environ.get("PIPELINE_REMOTE_DIR", "").strip()
    if env_override:
        print("\n" + "=" * 60)
        print("  REMOTE FOLDER")
        print("=" * 60)
        print(f"  [i] PIPELINE_REMOTE_DIR override: {env_override}")
        final = ensure_remote_path(uploader, env_override)
        return final if final else "/"

    print("\n" + "=" * 60)
    print("  REMOTE FOLDER")
    print("=" * 60)
    if suggested:
        print(f"\n  suggested: {suggested}")
        if ask_yes_no(f"  use '{suggested}'?", default_yes=True):
            final = ensure_remote_path(uploader, suggested)
            if final != "/" or suggested == "/":
                return final

    folders = []
    try:
        r = uploader.list_dir("/")
        if r.get("errno") == 0:
            folders = [it for it in r.get("list", []) if it.get("isdir") == 1]
    except Exception as e:
        print(f"  ⚠️  {e}")

    if folders:
        print("\n  folders at /:")
        for i, f in enumerate(folders, 1):
            print(f"    [{i}] {f.get('server_filename', '?')}")

    print(
        """
  number → existing folder   /  or Enter → root
  name → creates /name       /A/B/... → creates each segment
"""
    )
    choice = input("  choice [/]: ").strip()

    if choice in ("", "/"):
        return "/"
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(folders):
            return "/" + folders[idx].get("server_filename", "")
        return "/"
    target = choice if choice.startswith("/") else "/" + choice
    if not ask_yes_no(f"  create '{target}' if missing?"):
        return "/"
    final = ensure_remote_path(uploader, target)
    return final if final != "/" or target == "/" else "/"


# ============================================================
# DOWNLOAD MODE
# ============================================================
captured_links: list[str] = []
captured_filenames: list[str] = []
captured_metadata: list[tuple[str, float]] = []


async def inject_auth_cookies(context, cookies_dict: dict) -> int:
    if not cookies_dict:
        return 0
    cookie_objs = [
        {
            "name": name,
            "value": value,
            "domain": ".terabox.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        }
        for name, value in cookies_dict.items()
    ]
    await context.add_cookies(cookie_objs)
    return len(cookie_objs)


def try_extract_dlink(text: str):
    if not text:
        return
    for pat in DLINK_PATTERNS:
        for m in re.finditer(pat, text):
            link = m.group(0).replace("\\/", "/")
            if link not in captured_links:
                captured_links.append(link)
                print(f"\n  🎯 Captured (regex): {link[:130]}...")
    try:
        data = json.loads(text)
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in DLINK_KEYS and isinstance(v, str) and v.startswith("http"):
                        v = v.replace("\\/", "/")
                        if v not in captured_links:
                            captured_links.append(v)
                            print(f"\n  🎯 Captured (key={k}): {v[:130]}...")
                    stack.append(v)
                if "server_filename" in node:
                    fn = node["server_filename"]
                    if fn and fn not in captured_filenames:
                        captured_filenames.append(fn)
                        size = node.get("size", 0)
                        try:
                            size_mb = int(size) / 1024 / 1024
                        except (ValueError, TypeError):
                            size_mb = 0
                        captured_metadata.append((fn, size_mb))
                        print(f"  📄 Server filename: {fn}  ({size_mb:.2f} MB)")
            elif isinstance(node, list):
                stack.extend(node)
    except Exception:
        pass


async def handle_download_response(response):
    url = response.url
    if any(
        x in url
        for x in ["google", "facebook", "stripe", "analytics", "doubleclick"]
    ):
        return
    looks_relevant = (
        "/file/" in url
        or "share/list" in url
        or "/share/" in url
        or "api/shorturlinfo" in url
        or "list" in url
    )
    if looks_relevant:
        try_extract_dlink(url)
    ctype = response.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body = await response.text()
            try_extract_dlink(body)
        except Exception:
            pass


async def dismiss_download_modal(page) -> bool:
    await page.wait_for_timeout(500)
    positive_texts = [
        "continue downloading in browser",
        "continue in browser",
        "download with browser",
        "browser download",
        "still download",
        "continue download",
        "continue downloading",
        "continue",
        "confirm",
    ]
    negative_texts = [
        "open in",
        "terabox pc",
        "use app",
        "install",
        "open app",
        "client",
        "pc version",
    ]
    for txt in positive_texts:
        for tag in ["button", "a", "div[role='button']"]:
            selector = f"{tag}:has-text('{txt}')"
            try:
                locator = page.locator(selector).first
                if await locator.count() > 0:
                    btn_text = (await locator.inner_text()).strip().lower()
                    if any(neg in btn_text for neg in negative_texts):
                        continue
                    await locator.click(timeout=2000)
                    print(f"  ✓ Modal dismissed: clicked '{btn_text[:60]}'")
                    return True
            except Exception:
                continue
    for sel in [
        "div[role='dialog'] button",
        ".dialog button",
        ".modal button",
        ".ant-modal button",
        "div[class*='dialog'] button",
        "div[class*='modal'] button",
    ]:
        try:
            buttons = await page.query_selector_all(sel)
            for btn in buttons:
                try:
                    text = (await btn.inner_text()).strip().lower()
                except Exception:
                    continue
                if any(neg in text for neg in negative_texts):
                    continue
                if any(pos in text for pos in positive_texts):
                    await btn.click()
                    print(f"  ✓ Modal dismissed (fallback): '{text[:60]}'")
                    return True
        except Exception:
            continue
    return False


def pick_best_dlink(links):
    if not links:
        return None
    tier1 = [
        l for l in links if re.search(r"https?://d(-[a-z]{2,5})?\.terabox\.com/file/", l)
    ]
    if tier1:
        return max(tier1, key=len)
    ext_re = (
        r"\.(zip|mp4|mkv|pdf|rar|7z|mov|avi|m4a|mp3|png|jpg|jpeg|docx|xlsx|pptx|bin)(\?|$)"
    )
    tier2 = [l for l in links if "/file/" in l and re.search(ext_re, l)]
    if tier2:
        return max(tier2, key=len)
    tier3 = [l for l in links if "/file/" in l]
    if tier3:
        return max(tier3, key=len)
    tier4 = [l for l in links if re.search(ext_re, l)]
    if tier4:
        return max(tier4, key=len)
    return None


def resolve_redirect(dlink: str, cookies: str = "", referer: str = "", timeout: int = 15) -> dict:
    cmd = [
        "curl", "-s", "-D", "-", "-o", "/dev/null",
        "-H", f"User-Agent: {UA_UPLOAD}",
        "--max-time", str(timeout),
    ]
    if cookies:
        cmd += ["-H", f"Cookie: {cookies}"]
    if referer:
        cmd += ["-H", f"Referer: {referer}"]
    cmd.append(dlink)

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        headers_blob = r.stdout
    except Exception as e:
        return {"success": False, "error": str(e)}

    status_code = ""
    redirect_url = ""
    for line in headers_blob.splitlines():
        line = line.strip()
        if not status_code and line.startswith("HTTP/"):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                status_code = parts[1]
        elif line.lower().startswith("location:"):
            redirect_url = line.split(":", 1)[1].strip()
            break

    if not status_code:
        preview = headers_blob[:300].replace("\n", "\\n")
        return {"success": False, "error": f"no HTTP status (curl: {preview!r})"}
    if not redirect_url:
        return {"success": False, "error": f"HTTP {status_code}, no Location header"}

    parsed = urlparse(redirect_url)
    q = parse_qs(parsed.query)
    result = {
        "success": True,
        "redirect_url": redirect_url,
        "host": parsed.netloc,
        "filename": q.get("fin", [""])[0],
        "size": int(q.get("size", ["0"])[0]) if q.get("size") else 0,
        "region": q.get("region", [""])[0],
        "ccn": q.get("ccn", [""])[0],
    }
    if "expires" in q:
        try:
            exp = int(q["expires"][0])
            result["expires_ts"] = exp
            result["expires_dt"] = datetime.datetime.fromtimestamp(exp)
        except (ValueError, IndexError):
            pass
    return result


def print_redirect_info(info: dict):
    print(f"  ✅ redirect resolved")
    print(f"     CDN host:   {info['host']}")
    if info.get("filename"):
        print(f"     Filename:   {info['filename']}")
    if info.get("size"):
        print(f"     Size:       {info['size'] / 1024 / 1024:.2f} MB")
    if info.get("region"):
        print(
            f"     Region:     {info['region']}  "
            f"(your apparent country: {info.get('ccn', '?')})"
        )
    if "expires_dt" in info:
        delta = info["expires_dt"] - datetime.datetime.now()
        hours = delta.total_seconds() / 3600
        print(f"     Valid for:  ~{hours:.1f} hours")


def download_with_aria2(
    url: str,
    save_dir: Path,
    referer: str = "",
    cookies: str = "",
    threads: int = 16,
    out_filename: str = "",
    is_redirect: bool = False,
) -> Path | None:
    if not shutil.which("aria2c"):
        print("❌ aria2c not found. Install: brew install aria2")
        return None
    save_dir.mkdir(parents=True, exist_ok=True)
    threads = max(1, min(threads, 16))

    out_path: Path | None = None
    if out_filename:
        safe_name = out_filename.replace("/", "_").replace("\\", "_")
        out_path = save_dir / safe_name
        # purge stale local copy so aria2c can't short-circuit on --continue
        for stale in (out_path, Path(str(out_path) + ".aria2")):
            if stale.exists():
                try:
                    stale.unlink()
                    print(f"  [i] purged stale {stale.name}")
                except Exception:
                    pass

    before = set(save_dir.iterdir()) if save_dir.exists() else set()

    cmd = [
        "aria2c",
        f"--dir={save_dir}",
        f"--split={threads}",
        f"--max-connection-per-server={threads}",
        "--min-split-size=1M",
        "--continue=true",
        "--max-tries=10",
        "--retry-wait=3",
        "--timeout=60",
        f"--user-agent={UA_UPLOAD}",
        "--console-log-level=warn",
        "--summary-interval=3",
        "--file-allocation=none",
    ]
    if referer and not is_redirect:
        cmd.append(f"--referer={referer}")
    if cookies and not is_redirect:
        cmd.append(f"--header=Cookie: {cookies}")
    if out_path is not None:
        cmd.append(f"--out={out_path.name}")
    cmd.append(url)

    mode_label = "redirect URL" if is_redirect else "original dlink"
    print(f"\n[*] aria2c ({mode_label}, {threads} connections) ...")
    print(f"    saving to: {save_dir}\n")

    try:
        subprocess.run(cmd, check=True)
        print("\n✅ download complete.")
    except subprocess.CalledProcessError as e:
        if e.returncode == -13:
            print("\n✅ download complete (aria2c SIGPIPE — harmless).")
        else:
            print(f"\n❌ aria2c exit {e.returncode}")
            if e.returncode == 22:
                print("   → HTTP error (likely 403). dlink may have expired.")
            elif e.returncode == 3:
                print("   → Server rejected parallel ranges. Try fewer threads.")
            elif e.returncode == 28:
                print("   → invalid option value. Threads must be 1-16.")
            return None

    # Preferred: trust the exact path we told aria2c to write
    if out_path is not None:
        if out_path.exists() and out_path.stat().st_size > 0:
            return out_path
        print(f"  ⚠️  expected output {out_path.name} is missing or empty")
        return None

    # Fallback only when no --out was given
    after = set(save_dir.iterdir()) if save_dir.exists() else set()
    new_files = [
        p
        for p in (after - before)
        if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".aria2")
    ]
    if new_files:
        return max(new_files, key=lambda p: p.stat().st_mtime)
    candidates = [
        p
        for p in save_dir.iterdir()
        if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".aria2")
    ]
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)
    return None


def decrypt_one(path: Path, passphrase: str, out_dir: Path | None = None, auto_yes: bool = False):
    print(f"\n[*] reading {path}")
    try:
        encrypted = path.read_bytes()
    except Exception as e:
        print(f"  ❌ could not read: {e}")
        return False

    print(f"    {human_bytes(len(encrypted))} encrypted bytes")
    print(f"    [*] deriving key and decrypting ...")
    try:
        metadata, video = decrypt_blob(encrypted, passphrase)
    except Exception as e:
        print(f"  ❌ decryption failed: {type(e).__name__}: {e}")
        print(f"     (wrong passphrase, corrupted file, or not an ee_tb blob)")
        return False

    orig_name_raw = metadata.get("orig_name")
    orig_name = (
        str(orig_name_raw)
        if isinstance(orig_name_raw, str)
        else (path.stem + ".decrypted.mp4")
    )
    dest_dir = out_dir if out_dir else path.parent
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / orig_name

    if dest.exists():
        if auto_yes:
            print(f"  overwriting existing {dest.name}")
        elif not ask_yes_no(f"  {dest} exists — overwrite?", default_yes=False):
            print(f"  skipped: {dest.name}")
            return False

    dest.write_bytes(video)
    print(f"  ✅ decrypted → {dest}")
    print(f"     {human_bytes(len(video))}  |  meta: {metadata}")

    if auto_yes or ask_yes_no(f"  delete the source .bin?", default_yes=False):
        try:
            path.unlink()
            print(f"  🗑  deleted {path.name}")
        except Exception as e:
            print(f"  ⚠️  could not delete: {e}")
    return True


async def download_mode(
    start_url: str,
    save_dir: Path,
    threads: int,
    do_decrypt: bool = True,
    passphrase: str = "",
):
    global captured_links, captured_filenames, captured_metadata
    captured_links = []
    captured_filenames = []
    captured_metadata = []

    print("=" * 60)
    print(f"  TeraBox — DOWNLOAD MODE  (account {ACTIVE_ACCOUNT})")
    print("=" * 60)

    auth_cookies = load_auth_cookies_from_env()
    if auth_cookies:
        print(f"\n🔑 loaded {len(auth_cookies)} cookie(s) from .env "
              f"(account {ACTIVE_ACCOUNT})")
    if TERABOX_USERNAME and TERABOX_PASSWORD:
        print(f"🔐 loaded credentials: ✓ set")
    else:
        print(f"⚠️  no username/password in .env")

    save_dir.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        print("\n[*] launching Chrome ...")
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context(user_agent=UA_UPLOAD)

        if auth_cookies:
            n = await inject_auth_cookies(context, auth_cookies)
            print(f"  ✅ injected {n} cookie(s)")

        page = await context.new_page()
        page.on("response", handle_download_response)

        print(f"[*] opening: {start_url}")
        try:
            await page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"  ⚠️  nav failed: {e}")
        await page.wait_for_timeout(2000)

        if not await is_logged_in(context):
            print("\n[*] not logged in — running full login ...")
            ok = await do_login(page, context)
            if ok:
                try:
                    await page.goto(start_url, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1500)
                except Exception:
                    pass
        else:
            print("  ✅ already logged in")

        await persist_fresh_cookie(context)

        print("\n" + "=" * 60)
        print("  BROWSER IS OPEN — DO THIS:")
        print("=" * 60)
        print(
            """
  1. Navigate to the file you want (or the .bin if it's encrypted).
  2. Click Download (⬇ arrow / toolbar ⬇ / big button).
  3. If a dialog asks "Continue in browser" vs "Open in TeraBox PC":
     the script will auto-click "Continue in browser".
  4. Wait for "🎯 Captured" in THIS terminal.
  5. Watcher auto-stops ~5s after first capture.
"""
        )

        loop = asyncio.get_running_loop()
        start = loop.time()
        first_capture_time = None
        last_count = 0

        while True:
            now = loop.time()
            elapsed = now - start
            if elapsed >= DOWNLOAD_WATCH_TIMEOUT:
                print(
                    f"  ⏱  timed out after {DOWNLOAD_WATCH_TIMEOUT}s "
                    f"({len(captured_links)} dlink(s))"
                )
                break
            if captured_links and first_capture_time is None:
                first_capture_time = now
                print(
                    f"  ✅ first dlink captured — stopping in "
                    f"{DOWNLOAD_CAPTURE_GRACE}s"
                )
            if len(captured_links) > last_count:
                last_count = len(captured_links)
                first_capture_time = now
            if (
                first_capture_time is not None
                and (now - first_capture_time) >= DOWNLOAD_CAPTURE_GRACE
            ):
                print(f"  ✅ watcher done — {len(captured_links)} dlink(s)")
                break
            try:
                await dismiss_download_modal(page)
            except Exception:
                pass
            await page.wait_for_timeout(500)

        cookies = await context.cookies()
        cookie_header = "; ".join(
            f"{c.get('name', '')}={c.get('value', '')}" for c in cookies
        )
        await browser.close()

    if captured_filenames:
        print(f"\n📄 original filename(s) on TeraBox:")
        for fn, size_mb in captured_metadata:
            print(f"     • {fn}  ({size_mb:.2f} MB)")

    if not captured_links:
        print("\n❌ no download links captured.")
        print("   → most likely the browser-vs-app modal wasn't dismissed.")
        return

    print(f"\n✅ captured {len(captured_links)} dlink(s)")
    for i, link in enumerate(captured_links, 1):
        print(f"   [{i}] {link[:120]}...")

    chosen = pick_best_dlink(captured_links)
    if not chosen:
        print("\n❌ no dlink passed filtering.")
        return
    print(f"\n[*] selected: {chosen[:130]}...")

    print(f"\n[*] resolving redirect target ...")
    redirect_info = resolve_redirect(chosen, cookies=cookie_header, referer=start_url)

    if redirect_info["success"]:
        print_redirect_info(redirect_info)
        aria_url = redirect_info["redirect_url"]
        aria_cookies = ""
        aria_referer = ""
        aria_out = redirect_info.get("filename", "")
        aria_is_redirect = True
    else:
        print(f"  ⚠️  redirect resolution failed: {redirect_info.get('error', 'unknown')}")
        print(f"     → falling back to original dlink (cookies + referer)")
        aria_url = chosen
        aria_cookies = cookie_header
        aria_referer = start_url
        aria_out = ""
        aria_is_redirect = False

    if not ask_yes_no(f"\ndownload with aria2c ({threads} threads)?", default_yes=True):
        return

    downloaded = download_with_aria2(
        aria_url,
        save_dir,
        referer=aria_referer,
        cookies=aria_cookies,
        threads=threads,
        out_filename=aria_out,
        is_redirect=aria_is_redirect,
    )

    if not downloaded:
        print("\n⚠️  could not identify downloaded file.")
        return

    print(f"\n  ✅ downloaded: {downloaded}")
    print(f"     {human_bytes(downloaded.stat().st_size)}")

    if downloaded.suffix.lower() == ".bin" and do_decrypt:
        print(f"\n[*] .bin detected — offering decrypt")
        if not passphrase:
            passphrase = prompt_passphrase(confirm=False)
        decrypt_one(downloaded, passphrase, out_dir=None)
    elif downloaded.suffix.lower() == ".bin":
        print(f"  (use --decrypt '{downloaded}' later to decrypt it)")


# ============================================================
# per-episode pipeline (single-account, non-ghost)
# ============================================================
async def handle_episode(
    uploader,
    url,
    show,
    season,
    episode,
    remote_dir,
    wait_time,
    headless,
    encrypt=True,
    master=None,
    source_url="",
):
    tag = f"S{season:02d}E{episode:02d}"
    orig_filename = f"{sanitize(show)} - {tag}.mp4"

    if encrypt and master is not None:
        upload_filename = mask_name(master, show, season, episode)
        display = f"{upload_filename} ({tag})"
    else:
        upload_filename = orig_filename
        display = upload_filename

    print(f"\n{'=' * 62}\n  {tag}\n{'=' * 62}")

    if remote_file_exists(uploader, remote_dir, upload_filename):
        print(f"  [skip] already on TeraBox: {display}")
        return True, "skipped"

    print("  [*] capturing...")
    stream, cookie_header, referer = await capture_stream(
        url, season, episode, wait_time, headless
    )
    if not stream:
        print(f"  [fail] no stream")
        return False, "no-stream"
    print(f"  [+] {stream}")

    max_bytes = MAX_RAM_BYTES_ENCRYPT if encrypt else MAX_RAM_BYTES
    try:
        chunks, size = stream_to_memory(
            stream, cookie_header, referer, tag, max_bytes
        )
    except Exception as e:
        print(f"  [fail] streaming: {e}")
        return False, "stream-fail"

    if encrypt and master is not None:
        print(f"    [*] encrypting {human_bytes(size)} with AES-256-GCM ...")
        metadata = {
            "v": 1,
            "type": "episode",
            "orig_name": orig_filename,
            "show": show,
            "season": int(season),
            "episode": int(episode),
            "size": int(size),
            "created": iso_now(),
            "source": source_url,
        }
        try:
            encrypted_bytes = encrypt_blob(chunks, metadata, master)
        except Exception as e:
            chunks.clear()
            print(f"  [fail] encryption: {e}")
            return False, "encrypt-fail"

        enc_size = len(encrypted_bytes)
        print(
            f"    [✓] encrypted → {human_bytes(enc_size)} "
            f"(+{enc_size - size} bytes overhead)"
        )

        upload_chunks = [
            encrypted_bytes[i:i + CHUNK_SIZE] for i in range(0, enc_size, CHUNK_SIZE)
        ]
        del encrypted_bytes
        upload_size = enc_size
    else:
        upload_chunks = chunks
        upload_size = size
        chunks = []

    try:
        r = uploader.upload_from_memory(
            upload_filename,
            upload_chunks,
            upload_size,
            remote_dir,
            skip_rapid=encrypt,
        )
    finally:
        upload_chunks.clear()

    ok = r.get("errno") == 0
    if ok:
        append_manifest([{
            "timestamp": iso_now(),
            "account": ACTIVE_ACCOUNT,
            "type": "episode",
            "orig_name": orig_filename,
            "masked_name": upload_filename,
            "size": upload_size,
            "remote_dir": remote_dir,
            "fs_id": _extract_fs_id(r),
        }])
    return ok, "uploaded"


# ============================================================
# per-movie pipeline (single-account, non-ghost)
# ============================================================
async def handle_movie(
    uploader,
    url,
    title,
    year,
    remote_dir,
    wait_time,
    headless,
    master,
):
    tag = sanitize(title)
    if year:
        tag = f"{tag}_{year}"
    orig_filename = f"{tag}.mp4"

    upload_filename = mask_name_movie(master, title, year)
    display = f"{upload_filename} ({tag})"

    print(f"\n{'=' * 62}\n  {tag}\n{'=' * 62}")

    if remote_file_exists(uploader, remote_dir, upload_filename):
        print(f"  [skip] already on TeraBox: {display}")
        return True, "skipped"

    print("  [*] capturing...")
    stream, cookie_header, referer = await capture_movie_stream(
        url, wait_time, headless
    )
    if not stream:
        print(f"  [fail] no stream")
        return False, "no-stream"
    print(f"  [+] {stream}")

    try:
        chunks, size = stream_to_memory(
            stream, cookie_header, referer, tag, MAX_RAM_BYTES_ENCRYPT
        )
    except Exception as e:
        print(f"  [fail] streaming: {e}")
        return False, "stream-fail"

    print(f"    [*] encrypting {human_bytes(size)} with AES-256-GCM ...")
    metadata = {
        "v": 1,
        "type": "movie",
        "orig_name": orig_filename,
        "title": title,
        "year": year,
        "size": int(size),
        "created": iso_now(),
        "source": url,
    }
    try:
        encrypted_bytes = encrypt_blob(chunks, metadata, master)
    except Exception as e:
        chunks.clear()
        print(f"  [fail] encryption: {e}")
        return False, "encrypt-fail"

    enc_size = len(encrypted_bytes)
    print(
        f"    [✓] encrypted → {human_bytes(enc_size)} "
        f"(+{enc_size - size} bytes overhead)"
    )

    upload_chunks = [
        encrypted_bytes[i:i + CHUNK_SIZE] for i in range(0, enc_size, CHUNK_SIZE)
    ]
    del encrypted_bytes
    upload_size = enc_size

    try:
        r = uploader.upload_from_memory(
            upload_filename,
            upload_chunks,
            upload_size,
            remote_dir,
            skip_rapid=True,
        )
    finally:
        upload_chunks.clear()

    ok = r.get("errno") == 0
    if ok:
        append_manifest([{
            "timestamp": iso_now(),
            "account": ACTIVE_ACCOUNT,
            "type": "movie",
            "orig_name": orig_filename,
            "masked_name": upload_filename,
            "size": upload_size,
            "remote_dir": remote_dir,
            "fs_id": _extract_fs_id(r),
        }])
    return ok, "uploaded"


# ============================================================
# ghost upload (shard across all 3 accounts)
# ============================================================
async def _sniff_all_accounts() -> list[tuple[int, str, dict]] | None:
    """Sniff accounts 1..N sequentially. Returns [(n, cookie_header, tokens)].

    Any failure (no jsToken) aborts the whole thing.
    """
    sessions = []
    for n in range(1, NUM_ACCOUNTS + 1):
        print(f"\n{'#' * 62}")
        print(f"#  GHOST — sniffing account {n}/{NUM_ACCOUNTS}")
        print(f"{'#' * 62}")
        set_active_account(n)
        cookie_header, tokens = await terabox_sniff()
        if not tokens.get("jsToken"):
            print(f"  ❌ account {n}: no jsToken captured — aborting ghost")
            return None
        sessions.append((n, cookie_header, dict(tokens)))
    return sessions


async def _upload_ghost_shards(
    sessions: list[tuple[int, str, dict]],
    ghost_base: str,
    ciphertext: bytes,
    orig_filename: str,
    file_type: str,
    ghost_id: str,
    source_ref: str,
) -> bool:
    """Split ciphertext into 3 shards and upload one per account.

    Returns True iff all shards landed. On partial failure, successful shards
    remain on their accounts and are logged to the manifest (leave orphan).
    """
    shards = split_ghost(ciphertext, ghost_id, GHOST_SHARD_COUNT)
    total = GHOST_SHARD_COUNT
    ghost_folder = f"{ghost_base.rstrip('/')}/{ghost_id}"

    print(f"\n[*] ghost: {ghost_id}")
    print(f"[*] ghost_folder (all 3 accounts): {ghost_folder}")
    print(f"[*] shard sizes: "
          f"{', '.join(human_bytes(len(s)) for s in shards)}")

    manifest_rows = []
    all_ok = True
    for idx, (n, cookie_header, tokens) in enumerate(sessions):
        set_active_account(n)
        uploader = TeraBoxUploader(cookie_header, tokens)
        shard_name = shard_filename(ghost_id, idx + 1, total)
        shard_blob = shards[idx]

        print(f"\n{'=' * 62}")
        print(f"  shard {idx + 1}/{total}  →  account {n}")
        print(f"  {shard_name}  ({human_bytes(len(shard_blob))})")
        print(f"{'=' * 62}")

        try:
            ensure_remote_path(uploader, ghost_folder)
        except Exception as e:
            print(f"  ❌ account {n}: folder create failed: {e}")
            all_ok = False
            continue

        if remote_file_exists(uploader, ghost_folder, shard_name):
            print(f"  [skip] already present on account {n}: {shard_name}")
            manifest_rows.append({
                "timestamp": iso_now(),
                "account": n,
                "type": file_type + "_ghost_shard",
                "orig_name": orig_filename,
                "masked_name": shard_name,
                "size": len(shard_blob),
                "remote_dir": ghost_folder,
                "fs_id": "",
                "ghost_id": ghost_id,
                "ghost_shard": idx + 1,
                "ghost_total": total,
                "ghost_original_size": len(ciphertext),
            })
            continue

        upload_chunks = [
            shard_blob[j:j + CHUNK_SIZE]
            for j in range(0, len(shard_blob), CHUNK_SIZE)
        ]
        try:
            r = uploader.upload_from_memory(
                shard_name, upload_chunks, len(shard_blob),
                ghost_folder, skip_rapid=True,
            )
            if r.get("errno") != 0:
                print(f"  ⚠️  account {n} upload errno={r.get('errno')}")
                all_ok = False
                continue
            manifest_rows.append({
                "timestamp": iso_now(),
                "account": n,
                "type": file_type + "_ghost_shard",
                "orig_name": orig_filename,
                "masked_name": shard_name,
                "size": len(shard_blob),
                "remote_dir": ghost_folder,
                "fs_id": _extract_fs_id(r),
                "ghost_id": ghost_id,
                "ghost_shard": idx + 1,
                "ghost_total": total,
                "ghost_original_size": len(ciphertext),
            })
        except Exception as e:
            print(f"  ❌ account {n} shard upload failed: {type(e).__name__}: {e}")
            all_ok = False
        finally:
            upload_chunks.clear()

    if manifest_rows:
        append_manifest(manifest_rows)

    if not all_ok:
        print(f"\n  ⚠️  ghost upload INCOMPLETE — some shards missing.")
        print(f"     Successful shards remain on their accounts (orphans).")
        print(f"     To recover, re-run the same ghost upload; skip-check will")
        print(f"     detect existing shards and only upload missing ones.")
    return all_ok


async def run_upload_ghost_tv(url, show, season, episodes, headless,
                              wait_time, master):
    _start_job(f"Ghost TV · {sanitize(show)} S{int(season):02d}")

    print(f"\n[*] GHOST mode — sharding across accounts 1..{NUM_ACCOUNTS}")
    print(f"[*] {len(episodes)} episode(s) queued: {episodes}")

    sessions = await _sniff_all_accounts()
    if sessions is None:
        return

    _n1, _ch1, _tk1 = sessions[0]
    uploader1 = TeraBoxUploader(_ch1, _tk1)
    suggested = f"{DEFAULT_REMOTE_ROOT}/encrypted/Ghosts"
    ghost_base = pick_remote_folder(uploader1, suggested=suggested)

    if not ask_yes_no(
        f"\nstart ghost — {len(episodes)} ep(s) → {ghost_base}/<ghost_id>?", default_yes=True
    ):
        return

    ok_list, fail_list = [], []
    for i, ep in enumerate(episodes, 1):
        print(f"\n[{i}/{len(episodes)}]")
        ciphertext, orig_filename, mask = await capture_and_encrypt_episode(
            url, show, season, ep, wait_time, headless, master, source_url=url
        )
        tag = f"S{season:02d}E{ep:02d}"
        if ciphertext is None:
            fail_list.append(tag)
            continue

        ghost_id = mask[:-4]  # strip .bin
        success = await _upload_ghost_shards(
            sessions, ghost_base, ciphertext, orig_filename,
            "episode", ghost_id, source_ref=url,
        )
        if success:
            ok_list.append(tag)
        else:
            fail_list.append(tag)

    print("\n" + "=" * 62)
    print("  GHOST DONE")
    print("=" * 62)
    print(f"  complete:  {len(ok_list)}   {ok_list}")
    print(f"  failed:    {len(fail_list)}   {fail_list}")
    print()
    print("  reminder: keep your passphrase safe. Files cannot be")
    print("  recovered without it.")

    if fail_list and not ok_list:
        _status = "failed"
    elif fail_list:
        _status = "partial"
    else:
        _status = "complete"
    notify_job_end(_status, f"↑{len(ok_list)} ✗{len(fail_list)}")


async def run_upload_ghost_tv_batch(url, show, season, episodes, headless,
                                    wait_time, master, skip_existing: bool = True):
    """Batch ghost upload of a whole season.

    Differences from run_upload_ghost_tv:
      - Sniffs all 3 accounts ONCE (reused across every episode)
      - Fast-path skip: if all 3 shards already exist on their target
        accounts, skips the episode entirely (no capture, no encrypt)
      - Continues past individual episode failures
      - Final summary + notification
    """
    _start_job(f"Ghost batch · {sanitize(show)} S{int(season):02d}")

    print(f"\n[*] GHOST BATCH — {sanitize(show)} S{int(season):02d}")
    print(f"[*] {len(episodes)} episode(s) queued: {episodes}")
    print(f"[*] skip already-uploaded: {'yes' if skip_existing else 'no'}")
    print(f"[*] sharding across accounts 1..{NUM_ACCOUNTS}")

    sessions = await _sniff_all_accounts()
    if sessions is None:
        raise RuntimeError("sniff aborted (missing jsToken on one account)")

    # one uploader per account — reused for the fast-path pre-check
    uploaders: list[TeraBoxUploader] = []
    for n, ch, tk in sessions:
        set_active_account(n)
        uploaders.append(TeraBoxUploader(ch, tk))

    set_active_account(sessions[0][0])
    suggested = f"{DEFAULT_REMOTE_ROOT}/encrypted/Ghosts"
    ghost_base = pick_remote_folder(uploaders[0], suggested=suggested)

    if not ask_yes_no(
        f"\nstart ghost batch — {len(episodes)} ep(s) → {ghost_base}/<ghost_id>?",
        default_yes=True,
    ):
        print("  [i] cancelled")
        notify_job_end("no-op", "user cancelled")
        return

    def _episode_fully_present(ghost_id: str) -> bool:
        """True iff all shards exist on their expected accounts."""
        ghost_folder = f"{ghost_base.rstrip('/')}/{ghost_id}"
        for idx, up in enumerate(uploaders):
            name = shard_filename(ghost_id, idx + 1, GHOST_SHARD_COUNT)
            set_active_account(sessions[idx][0])
            if _item_present(up, ghost_folder, name) is not True:
                return False
        return True

    ok_list:   list[str] = []
    skip_list: list[str] = []
    fail_list: list[str] = []

    for i, ep in enumerate(episodes, 1):
        tag = f"S{season:02d}E{ep:02d}"
        print(f"\n[{i}/{len(episodes)}] {tag}")

        try:
            ghost_id = mask_name(master, show, season, ep)[:-4]

            if skip_existing and _episode_fully_present(ghost_id):
                print(f"  [skip] {tag} — all {GHOST_SHARD_COUNT} shards "
                      f"already present on their accounts")
                skip_list.append(tag)
                continue

            ciphertext, orig_filename, mask2 = await capture_and_encrypt_episode(
                url, show, season, ep, wait_time, headless, master,
                source_url=url,
            )
            if ciphertext is None:
                print(f"  [fail] {tag} — capture/encrypt failed")
                fail_list.append(tag)
                continue

            if mask2[:-4] != ghost_id:
                print(f"  [!!] ghost_id mismatch: {mask2[:-4]} != {ghost_id}")
                fail_list.append(tag)
                continue

            success = await _upload_ghost_shards(
                sessions, ghost_base, ciphertext, orig_filename,
                "episode", ghost_id, source_ref=url,
            )
            (ok_list if success else fail_list).append(tag)

        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"  [!!] {tag} raised: {type(e).__name__}: {e}")
            fail_list.append(tag)
            continue

    print("\n" + "=" * 62)
    print("  BATCH DONE")
    print("=" * 62)
    print(f"  uploaded: {len(ok_list)}   {ok_list}")
    print(f"  skipped:  {len(skip_list)}   {skip_list}")
    print(f"  failed:   {len(fail_list)}   {fail_list}")
    print()
    print("  reminder: keep your passphrase safe. Files cannot be")
    print("  recovered without it.")

    if fail_list and not ok_list and not skip_list:
        _status = "failed"
    elif fail_list:
        _status = "partial"
    else:
        _status = "complete"
    notify_job_end(_status,
                   f"↑{len(ok_list)} ↷{len(skip_list)} ✗{len(fail_list)}")


async def run_upload_ghost_movie(url, title, year, headless, wait_time, master):
    tag = sanitize(title)
    if year:
        tag = f"{tag}_{year}"

    _start_job(f"Ghost Movie · {tag}")

    print(f"\n[*] GHOST mode — sharding across accounts 1..{NUM_ACCOUNTS}")
    print(f"[*] Movie: {tag}")

    sessions = await _sniff_all_accounts()
    if sessions is None:
        return

    _n1, _ch1, _tk1 = sessions[0]
    uploader1 = TeraBoxUploader(_ch1, _tk1)
    suggested = f"{DEFAULT_REMOTE_ROOT}/encrypted/Ghosts"
    ghost_base = pick_remote_folder(uploader1, suggested=suggested)

    if not ask_yes_no(f"\nstart ghost → {ghost_base}/<ghost_id>?", default_yes=True):
        return

    ciphertext, orig_filename, mask = await capture_and_encrypt_movie(
        url, title, year, wait_time, headless, master
    )
    if ciphertext is None:
        print(f"  ❌ ghost capture/encrypt failed")
        return

    ghost_id = mask[:-4]
    success = await _upload_ghost_shards(
        sessions, ghost_base, ciphertext, orig_filename,
        "movie", ghost_id, source_ref=url,
    )

    print("\n" + "=" * 62)
    print("  GHOST DONE")
    print("=" * 62)
    if success:
        print(f"  ✅ uploaded: {tag}")
        print(f"     ghost_id: {ghost_id}")
        print(f"     folder:   {ghost_base}/{ghost_id}")
        notify_job_end("complete", f"ghost_id={ghost_id[:12]}…")
    else:
        print(f"  ⚠️  partial — see orphan notes above")
        notify_job_end("partial", f"ghost_id={ghost_id[:12]}…")


# ============================================================
# ghost reconstruct
# ============================================================
def _resolve_dlink_http_sync(account_n: int, remote_path: str):
    """Pure-HTTP dlink resolver. Returns (dlink, cookie_header) or ("", "")."""
    import requests as _req

    raw = _read_env_value(f"TERABOX_{account_n}_COOKIE")
    if not raw and account_n == 1:
        raw = _read_env_value("COOKIE_JSON") or _read_env_value("NDUS")
    if not raw:
        return "", ""
    ndus = raw
    if raw.startswith("{"):
        try:
            ndus = json.loads(raw).get("ndus", "")
        except Exception:
            pass
    if not ndus:
        return "", ""

    sess = _req.Session()
    sess.headers.update({
        "User-Agent": UA_UPLOAD,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    sess.cookies.set("ndus", ndus, domain=".terabox.com")

    r = sess.get(f"{WEB_HOST}/main", timeout=30, allow_redirects=True)
    if r.status_code != 200:
        return "", ""
    html = r.text

    js_token = ""
    bd_token = ""
    m = re.search(r'"jsToken":"([^"]+)"', html)
    if m:
        m2 = re.search(r'fn\("([A-Fa-f0-9]+)"\)', unquote(m.group(1)))
        if m2:
            js_token = m2.group(1)
    m = re.search(r'"bdstoken":"([A-Fa-f0-9]+)"', html)
    if m:
        bd_token = m.group(1)
    if not js_token:
        m = re.search(r'fn%28%22([A-Fa-f0-9]{30,})%22%29', html)
        if m:
            js_token = m.group(1)
    if not js_token:
        return "", ""

    remote_dir  = os.path.dirname(remote_path) or "/"
    remote_name = os.path.basename(remote_path)

    base = {
        "app_id": APP_ID,
        "channel": CHANNEL,
        "clienttype": CLIENTTYPE,
        "web": WEB,
        "bdstoken": bd_token,
        "jsToken": js_token,
        "dir": remote_dir,
        "order": "time",
        "desc": "1",
        "showempty": "0",
        "page": "1",
        "num": "200",
    }

    # attempt 1: /api/list?dlink=1
    try:
        p = dict(base); p["dlink"] = "1"
        qs = "&".join(f"{k}={_req.utils.quote(str(v), safe='')}" for k, v in p.items())
        rr = sess.get(f"{WEB_HOST}/api/list?{qs}", timeout=30,
                      headers={"Referer": f"{WEB_HOST}/main",
                               "X-Requested-With": "XMLHttpRequest"})
        j = rr.json()
        if j.get("errno") == 0:
            for it in j.get("list", []):
                if it.get("server_filename") == remote_name:
                    for k in ("dlink", "downloadLink", "download_link"):
                        if it.get(k):
                            cookie_header = "; ".join(
                                f"{c.name}={c.value}" for c in sess.cookies
                            )
                            return it[k], cookie_header
    except Exception as e:
        print(f"  [i] /api/list?dlink=1 failed: {e}")

    # attempt 2: /api/filemetas
    try:
        p = dict(base)
        p["target"] = json.dumps([remote_path])
        p["dlink"] = "1"
        qs = "&".join(f"{k}={_req.utils.quote(str(v), safe='')}" for k, v in p.items())
        rr = sess.get(f"{WEB_HOST}/api/filemetas?{qs}", timeout=30,
                      headers={"Referer": f"{WEB_HOST}/main",
                               "X-Requested-With": "XMLHttpRequest"})
        j = rr.json()
        if j.get("errno") == 0:
            info = j.get("info") or []
            if isinstance(info, list):
                for it in info:
                    for k in ("dlink", "downloadLink", "download_link"):
                        if it.get(k):
                            cookie_header = "; ".join(
                                f"{c.name}={c.value}" for c in sess.cookies
                            )
                            return it[k], cookie_header
    except Exception as e:
        print(f"  [i] /api/filemetas failed: {e}")

    return "", ""


async def _capture_one_dlink_via_http(
    account_n: int, save_dir: Path, threads: int,
    remote_path: str, out_name: str,
) -> tuple[Path | None, str, dict]:
    """Pure-HTTP shard download. No browser, no clicking."""
    set_active_account(account_n)

    print(f"\n  [*] HTTP resolving dlink for account {account_n} ...")
    print(f"      path: {remote_path}")

    dlink, cookie_header = await asyncio.to_thread(
        _resolve_dlink_http_sync, account_n, remote_path
    )
    if not dlink:
        print(f"  [!] HTTP dlink resolution failed for account {account_n}")
        return None, "", {}

    print(f"      dlink: {dlink[:100]}...")
    print(f"      cookies: {len(cookie_header)} chars")

    print(f"  [*] resolving redirect (with cookies) ...")
    info = resolve_redirect(
        dlink, cookies=cookie_header, referer=f"{WEB_HOST}/main"
    )
    if info.get("success"):
        print_redirect_info(info)
        url = info["redirect_url"]
        out = out_name or info.get("filename", "")
        path = download_with_aria2(
            url, save_dir, threads=threads,
            out_filename=out, is_redirect=True,
        )
    else:
        print(f"  [i] redirect failed — trying dlink directly (with cookies)")
        path = download_with_aria2(
            dlink, save_dir,
            referer=f"{WEB_HOST}/main",
            cookies=cookie_header,
            threads=threads,
            out_filename=out_name,
        )

    return path, cookie_header, {}


async def _capture_one_dlink(
    account_n: int, save_dir: Path, threads: int, out_name: str = ""
) -> tuple[Path | None, str, dict]:
    """Sniff account N, wait for user download click, aria2c, return
    (local_path, cookie_header, tokens). local_path is None on failure."""
    global captured_links, captured_filenames, captured_metadata
    captured_links = []
    captured_filenames = []
    captured_metadata = []

    set_active_account(account_n)
    auth_cookies = load_auth_cookies_from_env()
    cookie_header = ""

    print(f"\n{'=' * 62}")
    print(f"  ACCOUNT {account_n} — waiting for download click")
    print(f"{'=' * 62}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context(user_agent=UA_UPLOAD)
        await context.add_init_script(
            """
            // Block every common popup vector:
            //   1. window.open
            //   2. synthetic anchor clicks with target=_blank
            //   3. click events on target=_blank anchors (capture phase)
            window.open = function(){ return null; };
            const _origAnchorClick = HTMLAnchorElement.prototype.click;
            HTMLAnchorElement.prototype.click = function() {
                const t = this.getAttribute('target');
                if (t === '_blank' || t === 'blank') {
                    console.warn('blocked anchor.click → target=_blank');
                    return;
                }
                return _origAnchorClick.apply(this, arguments);
            };
            document.addEventListener('click', function(e) {
                const a = e.target && e.target.closest
                    ? e.target.closest('a[target=_blank]') : null;
                if (a) {
                    console.warn('blocked click on target=_blank');
                    e.preventDefault();
                    e.stopImmediatePropagation();
                }
            }, true);
            """
        )

        if auth_cookies:
            n = await inject_auth_cookies(context, auth_cookies)
            print(f"  ✅ injected {n} cookie(s)")

        page = await context.new_page()
        page.on("response", handle_download_response)

        try:
            await page.goto(f"{WEB_HOST}/main",
                            wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"  ⚠️  nav to /main failed: {e}")
            print(f"  [*] retrying once ...")
            try:
                await page.goto(f"{WEB_HOST}/main",
                                wait_until="domcontentloaded", timeout=90000)
            except Exception as e2:
                print(f"  ⚠️  second nav also failed: {e2}")
        await page.wait_for_timeout(2500)

        if not await is_logged_in(context):
            print("  [*] not logged in — running login ...")
            await do_login(page, context)
            try:
                await page.goto(f"{WEB_HOST}/main", wait_until="domcontentloaded",
                                timeout=60000)
                await page.wait_for_timeout(1500)
            except Exception:
                pass
        else:
            print("  ✅ already logged in")

        await persist_fresh_cookie(context)
        n_closed = await _dismiss_terabox_nuisances(page)
        if n_closed:
            print(f"  [i] dismissed {n_closed} nuisance popup(s)")

        print(f"\n  ▶ In Chrome: navigate to the shard, click ⬇ download.")
        print(f"    Save folder: {save_dir}")
        print(f"    Watching for dlink (up to {DOWNLOAD_WATCH_TIMEOUT}s)...\n")

        loop = asyncio.get_running_loop()
        start = loop.time()
        first_capture = None
        last_count = 0
        while True:
            now = loop.time()
            if now - start >= DOWNLOAD_WATCH_TIMEOUT:
                print(f"  ⏱ timed out ({len(captured_links)} dlink(s))")
                break
            if captured_links and first_capture is None:
                first_capture = now
            if len(captured_links) > last_count:
                last_count = len(captured_links)
                first_capture = now
            if first_capture and (now - first_capture) >= DOWNLOAD_CAPTURE_GRACE:
                print(f"  ✅ watcher done — {len(captured_links)} dlink(s)")
                break
            try:
                await dismiss_download_modal(page)
            except Exception:
                pass
            await page.wait_for_timeout(500)

        cookies = await context.cookies()
        cookie_header = "; ".join(
            f"{c.get('name', '')}={c.get('value', '')}" for c in cookies
        )
        await browser.close()

    if not captured_links:
        print(f"  ❌ no dlink captured for account {account_n}")
        return None, cookie_header, dict(sniffed_tokens)

    chosen = pick_best_dlink(captured_links)
    if not chosen:
        print(f"  ❌ no viable dlink for account {account_n}")
        return None, cookie_header, dict(sniffed_tokens)

    print(f"\n[*] resolving redirect ...")
    info = resolve_redirect(chosen, cookies=cookie_header,
                            referer=f"{WEB_HOST}/main")

    if info["success"]:
        print_redirect_info(info)
        url = info["redirect_url"]
        out = out_name or info.get("filename", "")
        path = download_with_aria2(
            url, save_dir, threads=threads,
            out_filename=out, is_redirect=True,
        )
    else:
        print(f"  ⚠️ redirect failed: {info.get('error')}")
        path = download_with_aria2(
            chosen, save_dir, referer=f"{WEB_HOST}/main",
            cookies=cookie_header, threads=threads,
            out_filename=out_name,
        )
    return path, cookie_header, dict(sniffed_tokens)


async def delete_via_ui(account_n: int, remote_dir: str, filename: str,
                       headless: bool = False) -> bool:
    """Delete a file by driving the TeraBox web UI.

    Navigate → hover row → click trash icon → click 'Move' in dialog.
    Bypasses the API's errno 450016 ('need verify') gate.
    """
    from urllib.parse import quote
    set_active_account(account_n)
    auth_cookies = load_auth_cookies_from_env()

    print(f"\n  [🗑] UI delete — account {account_n}")
    print(f"       {remote_dir}/{filename}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(user_agent=UA_UPLOAD)

        if auth_cookies:
            n = await inject_auth_cookies(context, auth_cookies)
            print(f"  ✅ injected {n} cookie(s)")

        page = await context.new_page()

        folder_url = f"{WEB_HOST}/main?category=all&path={quote(remote_dir)}"
        print(f"  [*] opening: {folder_url}")
        try:
            await page.goto(folder_url, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"  ⚠️  nav: {e}")
        await page.wait_for_timeout(4000)

        if not await is_logged_in(context):
            print("  [*] not logged in — running login")
            await do_login(page, context)
            try:
                await page.goto(folder_url, wait_until="domcontentloaded",
                                timeout=60000)
                await page.wait_for_timeout(3000)
            except Exception:
                pass

        await persist_fresh_cookie(context)
        n_closed = await _dismiss_terabox_nuisances(page)
        if n_closed:
            print(f"  [i] dismissed {n_closed} nuisance popup(s)")

        # 1) locate the file row
        print(f"  [*] locating '{filename}' ...")
        file_el = None
        for sel in [f'text="{filename}"', f'[title="{filename}"]',
                    f'[data-name="{filename}"]']:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0:
                    file_el = loc
                    print(f"  ✓ found via {sel}")
                    break
            except Exception:
                continue
        if file_el is None:
            try:
                loc = page.get_by_text(filename, exact=False).first
                if await loc.count() > 0:
                    file_el = loc
                    print(f"  ✓ found via partial text match")
            except Exception:
                pass

        if file_el is None:
            print(f"  ❌ file not found in current folder view")
            try:
                print(f"  [debug] current URL: {page.url}")
                names = await page.locator('[class*="name" i]').all_inner_texts()
                print(f"  [debug] visible names (first 30):")
                for t in names[:30]:
                    if t.strip():
                        print(f"      {t[:80]!r}")
            except Exception:
                pass
            await browser.close()
            return False

        # 2) locate the row container element (parent wrapper of the file)
        print(f"  [*] locating row container ...")
        row_el = None
        for xp in [
            "xpath=ancestor::*[contains(@class,'file-item')][1]",
            "xpath=ancestor::*[contains(@class,'list-item')][1]",
            "xpath=ancestor::li[1]",
            "xpath=ancestor::tr[1]",
            "xpath=ancestor::*[contains(@class,'item')][1]",
            "xpath=parent::*",
        ]:
            try:
                loc = file_el.locator(xp).first
                if await loc.count() > 0:
                    row_el = loc
                    print(f"  ✓ row container via {xp}")
                    break
            except Exception:
                continue

        # 3-4) hover + retry loop for hover-mounted trash icon
        print(f"  [*] looking for row-scoped trash icon ...")
        trash_selectors = [
            '[class*="trash" i]',
            '[class*="delete" i]',
            '[class*="remove" i]',
            '[class*="del-" i]',
            '[title*="delete" i]',
            '[title*="trash" i]',
            '[aria-label*="delete" i]',
            '[aria-label*="trash" i]',
            '[data-action="delete" i]',
            '[data-action="trash" i]',
            'svg[class*="trash" i]',
            'svg[class*="delete" i]',
            'i[class*="trash" i]',
            'i[class*="delete" i]',
        ]

        clicked = False
        for attempt in range(1, 6):     # 5 tries × ~1.2s = ~6s window
            # re-hover every attempt (mouse may have drifted after nav)
            try:
                await file_el.hover(timeout=4000)
            except Exception:
                try:
                    if row_el is not None:
                        await row_el.hover(timeout=3000)
                except Exception:
                    pass
            await page.wait_for_timeout(1200)

            if row_el is None:
                continue

            for sel in trash_selectors:
                try:
                    loc = row_el.locator(sel)
                    c = await loc.count()
                except Exception:
                    continue
                if c == 0:
                    continue
                for i in range(c - 1, -1, -1):
                    try:
                        el = loc.nth(i)
                        if not await el.is_visible():
                            continue
                        await el.click(timeout=3000, force=True)
                        print(f"  ✓ clicked row trash "
                              f"(sel={sel!r}, idx={i}/{c}, try={attempt})")
                        clicked = True
                        break
                    except Exception:
                        continue
                if clicked:
                    break
            if clicked:
                break
            print(f"    [~] row trash not visible yet (try {attempt}/5)")

        if not clicked:
            print(f"  ⚠️  no row-scoped trash icon found "
                  f"— dumping row HTML for diagnosis")
            try:
                if row_el is not None:
                    html = await row_el.evaluate("el => el.outerHTML")
                else:
                    html = await file_el.evaluate(
                        "el => el.closest('li,tr,[class*=item]')?.outerHTML "
                        "|| el.parentElement?.outerHTML || ''"
                    )
                print(f"  [debug] row HTML (first 4000 chars):\n{html[:4000]}")
            except Exception as e:
                print(f"  [debug] dump failed: {e}")
            await browser.close()
            return False

        # 5) find confirm button in modal / popup
        await page.wait_for_timeout(800)
        print(f"  [*] waiting for confirm dialog (up to 15s) ...")

        async def _find_visible_dialog():
            """Return (dialog_locator, selector) or (None, '') if nothing visible yet.

            Prefers WRAPPER-level nodes (which contain both header + footer
            buttons). Falls back to inner classes only if no wrapper matches.
            """
            contexts: list = [page]
            try:
                for f in page.frames:
                    if f != page.main_frame:
                        contexts.append(f)
            except Exception:
                pass

            wrapper_sels = [
                '.u-dialog__wrapper:visible',
                '.u-dialog:visible',
                '.ant-modal-wrap:visible',
                '.ant-modal:visible',
                '[role="dialog"]:visible',
                '.dialog-modal:visible',
                '.component-base-modal-index:visible',
            ]
            fallback_sels = [
                '[class*="dialog" i]:visible',
                '[class*="modal" i]:visible',
                '[class*="confirm" i]:visible',
            ]

            for ctx in contexts:
                for sel_list in (wrapper_sels, fallback_sels):
                    for sel in sel_list:
                        try:
                            loc = ctx.locator(sel)
                            cnt = await loc.count()
                        except Exception:
                            continue
                        for i in range(cnt):
                            d = loc.nth(i)
                            try:
                                if not await d.is_visible():
                                    continue
                                cls = ((await d.get_attribute("class")) or "").lower()
                                txt = ((await d.inner_text()) or "").strip()
                                if "cashier-iframe" in cls and not txt:
                                    continue
                                if not txt:
                                    continue
                                low = txt.lower()
                                if any(s in low for s in (
                                    "recycle bin description",
                                    "retention period",
                                    "large file upload",
                                    "开通会员",
                                    "cashier",
                                    "upload complete",
                                    "security verification",
                                )):
                                    continue
                                # node must actually contain a button-like child
                                has_btn = False
                                for bsel in (
                                    'button',
                                    '[role="button"]',
                                    '.modal-btn',
                                    '[class*="btn" i]',
                                ):
                                    try:
                                        if await d.locator(bsel).count() > 0:
                                            has_btn = True
                                            break
                                    except Exception:
                                        continue
                                if not has_btn:
                                    # walk up to an ancestor with buttons
                                    try:
                                        up = d.locator(
                                            "xpath=ancestor-or-self::*["
                                            "contains(@class,'u-dialog__wrapper')"
                                            " or contains(@class,'u-dialog')"
                                            " or contains(@class,'ant-modal')"
                                            " or contains(@class,'dialog-modal')"
                                            "][1]"
                                        )
                                        if await up.count() > 0:
                                            u = up.first
                                            if await u.is_visible():
                                                d = u
                                                has_btn = True
                                    except Exception:
                                        pass
                                if not has_btn:
                                    continue
                                return d, sel
                            except Exception:
                                continue
            return None, ""

        dialog = None
        dialog_sel = ""
        for tick in range(75):   # 75 × 200ms = 15s
            dialog, dialog_sel = await _find_visible_dialog()
            if dialog:
                print(f"  ✓ dialog visible (sel={dialog_sel!r})")
                try:
                    preview = ((await dialog.inner_text()) or "")[:140]
                    print(f"      content: {preview!r}")
                except Exception:
                    pass
                break
            await page.wait_for_timeout(200)

        if not dialog:
            print(f"  ❌ no visible dialog appeared within 15s")
            # diagnostic: list EVERY dialog-ish element with size, not just .first
            try:
                dump = await page.evaluate(
                    """
                    () => {
                        const out = [];
                        document.querySelectorAll(
                            '[class*=dialog],[class*=modal],[class*=confirm],[role=dialog]'
                        ).forEach(e => {
                            const r = e.getBoundingClientRect();
                            const s = getComputedStyle(e);
                            out.push({
                                cls: (e.className || '').toString().slice(0, 80),
                                size: r.width + 'x' + r.height,
                                display: s.display,
                                visibility: s.visibility,
                                opacity: s.opacity,
                                text: (e.innerText || '').slice(0, 60),
                            });
                        });
                        return out;
                    }
                    """
                )
                print(f"  [debug] {len(dump)} dialog-ish element(s) on page:")
                for i, d in enumerate(dump):
                    print(f"      [{i}] cls={d['cls']!r}")
                    print(f"          size={d['size']} display={d['display']} "
                          f"vis={d['visibility']} op={d['opacity']}")
                    print(f"          text={d['text']!r}")
            except Exception as e:
                print(f"  [debug] dialog dump failed: {e}")
            # also list frames
            try:
                frames = page.frames
                print(f"  [debug] page has {len(frames)} frame(s):")
                for i, f in enumerate(frames):
                    print(f"      [{i}] {f.url[:120]}")
            except Exception:
                pass
            await browser.close()
            return False

        # ---- 5) click the confirm button ('Move') ----
        print(f"  [*] looking for confirm button inside dialog ...")
        confirmed = False

        # ---- FAST PATH: known TeraBox delete-dialog selectors ----
        # These are what the real dialog renders (confirmed in the wild):
        #   <div class="footer-btn-list">
        #     <div class="delete-box-btn cancel-btn">Cancel</div>
        #     <div class="delete-box-btn delete-btn">Move</div>
        #   </div>
        fast_sels = [
            '.delete-box-btn.delete-btn',
            '[class*="delete-box-btn"][class*="delete"]',
            '.footer-btn-list [class*="delete-btn"]',
            '[class*="footer-btn-list"] [class*="delete"]',
        ]
        for sel in fast_sels:
            try:
                loc = page.locator(sel)
                cnt = await loc.count()
            except Exception:
                continue
            for i in range(cnt):
                btn = loc.nth(i)
                try:
                    if not await btn.is_visible():
                        continue
                    txt = ((await btn.inner_text()) or "").strip()
                except Exception:
                    continue
                low = txt.lower()
                if any(x in low for x in ["cancel", "取消", "close", "关闭"]):
                    continue
                try:
                    await btn.click(timeout=2000, force=True)
                    print(f"  ✓ clicked confirm (fast-path): "
                          f"{txt!r} sel={sel!r}")
                    confirmed = True
                    break
                except Exception:
                    continue
            if confirmed:
                break

        confirm_texts = [
            "Move", "移动", "Confirm", "Delete", "删除",
            "确定", "OK", "Yes", "是", "Continue", "继续",
        ]
        negative_texts = ["cancel", "取消", "close", "关闭"]

        # Preferred: role-based lookup inside the dialog
        for t in confirm_texts:
            try:
                btn = dialog.get_by_role("button", name=t, exact=False).first
                if await btn.count() > 0 and await btn.is_visible():
                    txt = ((await btn.inner_text()) or "").strip()
                    if any(x in txt.lower() for x in negative_texts):
                        continue
                    await btn.click(timeout=3000, force=True)
                    print(f"  ✓ clicked confirm: {txt!r} (role=button)")
                    confirmed = True
                    break
            except Exception:
                pass
            if confirmed:
                break

        # Fallback: has-text on any clickable inside the dialog
        if not confirmed:
            for t in confirm_texts:
                for tag in [
                    "button",
                    "a",
                    "div[role='button']",
                    "[role='button']",
                    ".modal-btn",
                    "[class*='btn']",
                    "[class*='button']",
                ]:
                    sel = f"{tag}:has-text('{t}')"
                    try:
                        loc = dialog.locator(sel)
                        cnt = await loc.count()
                    except Exception:
                        continue
                    for i in range(cnt):
                        btn = loc.nth(i)
                        try:
                            if not await btn.is_visible():
                                continue
                            txt = ((await btn.inner_text()) or "").strip()
                        except Exception:
                            continue
                        if not txt:
                            continue
                        if any(x in txt.lower() for x in negative_texts):
                            continue
                        await btn.click(timeout=3000, force=True)
                        print(f"  ✓ clicked confirm: {txt!r} (via {sel})")
                        confirmed = True
                        break
                    if confirmed:
                        break
                if confirmed:
                    break

        # Page-wide fallback: if the dialog-local search missed (dialog
        # matched only its header, buttons live in a sibling footer),
        # look for Move/Cancel/Yes buttons anywhere on the page.
        if not confirmed:
            print(f"  [*] dialog-local search missed — trying page-wide ...")
            page_btn_sels = [
                'button:has-text("Move")',
                'button:has-text("Confirm")',
                'button:has-text("Yes")',
                'button:has-text("OK")',
                '[role="button"]:has-text("Move")',
                '.modal-btn.main-btn',
                'button.main-btn',
                '[class*="primary" i][class*="btn" i]',
                '[class*="btn" i][class*="primary" i]',
                '[class*="btn" i][class*="confirm" i]',
                '[class*="btn" i][class*="ok" i]',
                '.u-dialog__footer button',
                '[class*="dialog" i] [class*="footer" i] button',
            ]
            for sel in page_btn_sels:
                try:
                    loc = page.locator(sel)
                    cnt = await loc.count()
                except Exception:
                    continue
                for i in range(cnt):
                    btn = loc.nth(i)
                    try:
                        if not await btn.is_visible():
                            continue
                        txt = ((await btn.inner_text()) or "").strip()
                    except Exception:
                        continue
                    if not txt:
                        continue
                    low = txt.lower()
                    if any(x in low for x in ["cancel", "取消", "close", "关闭"]):
                        continue
                    try:
                        await btn.click(timeout=3000, force=True)
                        print(f"  ✓ clicked confirm (page-wide): "
                              f"{txt!r} (sel={sel!r})")
                        confirmed = True
                        break
                    except Exception:
                        continue
                if confirmed:
                    break

        # Last resort: climb ancestors of the matched dialog element and
        # look for a Move/Confirm button at each level. Handles the case where
        # the matched "dialog" is really just the header, and buttons live
        # inside a parent wrapper (with class names we can't predict).
        if not confirmed:
            print(f"  [*] dialog-local and page-wide both missed — "
                  f"climbing ancestors of matched dialog ...")
            node = dialog
            for level in range(8):
                try:
                    dump = await node.evaluate(
                        """
                        el => {
                            const out = [];
                            el.querySelectorAll(
                                'button, [role=button], .modal-btn, '
                                + '[class*=btn], [class*=Btn], '
                                + '[class*=confirm], [class*=Confirm]'
                            ).forEach(b => {
                                const t = (b.innerText || '').trim().slice(0, 40);
                                const c = (b.className || '').toString().slice(0, 70);
                                const tag = b.tagName;
                                out.push({tag: tag, cls: c, text: t});
                            });
                            return out;
                        }
                        """
                    )
                except Exception:
                    dump = []

                if dump:
                    print(f"    [level {level}] {len(dump)} button-ish descendant(s):")
                    for b in dump[:10]:
                        print(f"      <{b['tag']}> cls={b['cls']!r} text={b['text']!r}")

                    # try to click a Move/Confirm at this level
                    for t in ["Move", "移动", "Confirm", "Delete", "删除",
                              "确定", "Yes", "是", "OK", "Continue"]:
                        for sel in [
                            f'button:has-text("{t}")',
                            f'[role=button]:has-text("{t}")',
                            f'[class*=btn]:has-text("{t}")',
                            f'[class*=Btn]:has-text("{t}")',
                            f'[class*=confirm]:has-text("{t}")',
                        ]:
                            try:
                                loc = node.locator(sel)
                                cnt = await loc.count()
                            except Exception:
                                continue
                            for i in range(cnt):
                                btn = loc.nth(i)
                                try:
                                    if not await btn.is_visible():
                                        continue
                                    txt = ((await btn.inner_text()) or "").strip()
                                except Exception:
                                    continue
                                low = txt.lower()
                                if any(x in low for x in
                                       ["cancel", "取消", "close", "关闭"]):
                                    continue
                                try:
                                    await btn.click(timeout=2000, force=True)
                                    print(f"    ✓ clicked confirm at level "
                                          f"{level}: {txt!r} (sel={sel!r})")
                                    confirmed = True
                                    break
                                except Exception:
                                    continue
                            if confirmed:
                                break
                        if confirmed:
                            break
                    if confirmed:
                        break

                # climb one level
                try:
                    parent = node.locator("xpath=..").first
                    if await parent.count() == 0:
                        break
                    node = parent
                except Exception:
                    break

        if not confirmed:
            print(f"  ❌ confirm button not found after ancestor climb")
            try:
                # dump 6 levels of ancestors for the next iteration
                chain = await dialog.evaluate(
                    """
                    el => {
                        const out = [];
                        let n = el;
                        for (let i = 0; i < 6 && n; i++) {
                            const cls = (n.className || '').toString().slice(0, 90);
                            const tag = n.tagName;
                            const txt = (n.innerText || '').slice(0, 80)
                                          .replace(/\n/g, ' | ');
                            out.push(`[${i}] <${tag}> cls=${cls} text=${txt}`);
                            n = n.parentElement;
                        }
                        return out.join('\n');
                    }
                    """
                )
                print(f"  [debug] ancestor chain of matched dialog:\n{chain}")
            except Exception as e:
                print(f"  [debug] ancestor dump failed: {e}")
            await browser.close()
            return False

        await page.wait_for_timeout(2500)
        print(f"  ✅ delete UI flow completed for account {account_n}")
        await browser.close()
        return True


async def delete_folder_via_ui(account_n: int, folder_path: str,
                              headless: bool = False) -> bool:
    """Delete a folder by driving the UI — reuses delete_via_ui.

    Navigates to the folder's PARENT and clicks the trash on the folder
    row. TeraBox treats folder rows identically to file rows.
    """
    folder_path = "/" + folder_path.strip("/")
    parts = folder_path.strip("/").split("/")
    if len(parts) < 2:
        print(f"  ⚠️  refusing to UI-delete top-level folder {folder_path!r}")
        return False
    name = parts[-1]
    parent = "/" + "/".join(parts[:-1])
    return await delete_via_ui(account_n, parent, name, headless=headless)


async def ghost_reconstruct(ghost_folder: str, save_dir: Path, threads: int = 16):
    ghost_folder = "/" + ghost_folder.strip("/")
    folder_basename = ghost_folder.rstrip("/").split("/")[-1]
    if not folder_basename:
        print("  ❌ invalid ghost folder")
        return

    # guard against the "<ghost_id>" placeholder being pasted verbatim
    if "<" in folder_basename or ">" in folder_basename:
        print(f"  ❌ folder basename {folder_basename!r} still contains "
            f"angle brackets — replace <ghost_id> with the actual 32-char "
            f"ghost id (e.g. e140e78d7e73a0e630d0b5c4e6305cd1).")
        return

    _start_job(f"Reconstruct · {folder_basename[:12]}…")

    print("=" * 62)
    print("  GHOST RECONSTRUCT")
    print("=" * 62)
    print(f"  Ghost folder: {ghost_folder}")
    print(f"  Ghost id:     {folder_basename}")
    print(f"  Save folder:  {save_dir}")
    print()
    print(f"  Expected shards (one per account):")
    for i in range(GHOST_SHARD_COUNT):
        print(f"    account {i + 1}: {shard_filename(folder_basename, i + 1, GHOST_SHARD_COUNT)}")

    save_dir.mkdir(parents=True, exist_ok=True)

    local_shard_paths: list[Path] = []
    sessions: list[tuple[int, str, dict]] = []

    use_http = (os.environ.get("PIPELINE_HTTP_DLINK") == "1"
                or os.environ.get("PIPELINE_NONINTERACTIVE") == "1")

    for i in range(GHOST_SHARD_COUNT):
        n = i + 1
        shard_name = shard_filename(folder_basename, i + 1, GHOST_SHARD_COUNT)
        print(f"\n{'#' * 62}")
        print(f"#  SHARD {n}/{GHOST_SHARD_COUNT}  (account {n})")
        print(f"{'#' * 62}")

        if use_http:
            remote_path = f"{ghost_folder.rstrip('/')}/{shard_name}"
            path, cookie_header, tokens = await _capture_one_dlink_via_http(
                n, save_dir, threads,
                remote_path=remote_path,
                out_name=shard_name,
            )
        else:
            path, cookie_header, tokens = await _capture_one_dlink(
                n, save_dir, threads, out_name=shard_name
            )

        if path is None:
            print(f"\n  ❌ failed to fetch shard {n}. Aborting reconstruct.")
            notify_job_end("failed", f"shard {n} fetch failed")
            return
        local_shard_paths.append(path)
        sessions.append((n, cookie_header, tokens))

    print(f"\n[*] reading {len(local_shard_paths)} shard(s) ...")
    blobs = []
    for p in local_shard_paths:
        blobs.append(p.read_bytes())
        print(f"    • {p.name}  ({human_bytes(len(blobs[-1]))})")

    try:
        ghost_id, ciphertext = reassemble_ghost(blobs)
    except Exception as e:
        print(f"  ❌ reassembly failed: {e}")
        notify_job_end("failed", f"reassembly: {e}")
        return
    print(f"  ✅ reassembled {human_bytes(len(ciphertext))} "
        f"(ghost_id={ghost_id})")

    passphrase = prompt_passphrase(confirm=False)
    try:
        metadata, video = decrypt_blob(ciphertext, passphrase)
    except Exception as e:
        print(f"  ❌ decryption failed: {type(e).__name__}: {e}")
        notify_job_end("failed", f"decrypt: {type(e).__name__}")
        return

    orig_name = str(metadata.get("orig_name") or f"{ghost_id}.mp4")
    dest = save_dir / orig_name
    if dest.exists():
        if not ask_yes_no(f"  {dest} exists — overwrite?", default_yes=False):
            print(f"  skipped: {dest.name}")
            return
    dest.write_bytes(video)
    print(f"  ✅ decrypted → {dest}")
    print(f"     {human_bytes(len(video))}  |  meta: {metadata}")

    # cleanup remote — try API first, fall back to UI on 450016 "need verify"
        # cleanup remote — try API first, fall back to UI on 450016 "need verify"
    if ask_yes_no(f"\n  delete the {GHOST_SHARD_COUNT} shards from TeraBox?",
                default_yes=False):
        for idx, (n, cookie_header, tokens) in enumerate(sessions):
            set_active_account(n)
            uploader = TeraBoxUploader(cookie_header, tokens)
            shard_name = shard_filename(ghost_id, idx + 1, GHOST_SHARD_COUNT)

            ok, resp = uploader.delete_remote_file(ghost_folder, shard_name)
            if ok:
                print(f"  🗑  account {n}: deleted {shard_name} (API)")
                continue

            errno = resp.get("errno") if isinstance(resp, dict) else None
            print(f"  ⚠️  account {n}: API delete failed (errno={errno})")
            if errno == 450016:
                print(f"  [i] errno 450016 = need verify — trying UI delete ...")
                ui_ok = await delete_via_ui(n, ghost_folder, shard_name)
                if ui_ok:
                    print(f"  🗑  account {n}: deleted {shard_name} (UI)")
                else:
                    print(f"  ❌ account {n}: UI delete also failed")

        # NEW — remove the now-empty ghost folder on each account
        if ask_yes_no(f"\n  also delete the ghost folder "
                    f"({ghost_id}) on each account?", default_yes=False):
            for idx, (n, cookie_header, tokens) in enumerate(sessions):
                set_active_account(n)
                uploader = TeraBoxUploader(cookie_header, tokens)
                ok, resp = uploader.delete_remote_folder(ghost_folder)
                if ok:
                    print(f"  🗑  account {n}: deleted folder "
                        f"{ghost_folder} (API)")
                    continue
                errno = resp.get("errno") if isinstance(resp, dict) else None
                print(f"  ⚠️  account {n}: folder API delete failed "
                    f"(errno={errno})")
                if errno == 450016:
                    print(f"  [i] errno 450016 = need verify — "
                          f"trying UI folder delete ...")
                    ui_ok = await delete_folder_via_ui(n, ghost_folder)
                    if ui_ok:
                        print(f"  🗑  account {n}: deleted folder "
                              f"{ghost_folder} (UI)")
                    else:
                        print(f"  ❌ account {n}: folder UI delete also failed")
    # cascade-delete empty parents (independent of shard/folder deletes)
    if ask_yes_no(
        "\n  cascade-delete empty parent folders above the ghost folder?",
        default_yes=False,
    ):
        await cascade_empty_parents(sessions, ghost_folder, stop_at="/")

    # cleanup local
    if ask_yes_no(f"  delete local shard files?", default_yes=True):
        for p in local_shard_paths:
            try:
                p.unlink()
                print(f"  🗑  deleted {p.name}")
            except Exception as e:
                print(f"  ⚠️  could not delete {p.name}: {e}")

    notify_job_end("complete", f"→ {orig_name}")


def _item_present(uploader, folder, name):
    """Return True / False / None (unknown).

    Uses list_dir. errno < 0 means "not found" family → return False.
    errno > 0 means a real error (auth, verify, etc.) → return None.
    """
    try:
        r = uploader.list_dir(folder)
    except Exception:
        return None
    errno = r.get("errno")
    if errno != 0:
        if isinstance(errno, int) and errno < 0:
            return False
        return None
    for it in r.get("list", []):
        if it.get("server_filename") == name:
            return True
    return False


async def cascade_empty_parents(sessions, start_folder: str,
                                stop_at: str = "/"):
    """Walk up the parent chain, ONE LEVEL AT A TIME.

    Multi-account safety:
      - Every ancestor is scanned on ALL accounts before anything is deleted.
      - errno < 0 (path not found) is treated as "empty/absent" — no abort.
      - If all accounts empty        → offer to delete on all.
      - If some accounts empty, some not → offer to delete ONLY the empty
        ones, show what's in the non-empty ones, then STOP.
      - If any account errors (errno > 0, network) → STOP, no delete.
    """
    start_folder = "/" + start_folder.strip("/")
    parts = [x for x in start_folder.strip("/").split("/") if x]
    stop_parts = [x for x in stop_at.strip("/").split("/") if x]

    parents = []
    for i in range(len(parts) - 1, len(stop_parts), -1):
        parents.append("/" + "/".join(parts[:i]))

    if not parents:
        return

    print()
    print("  [*] cascading parents — MULTI-ACCOUNT scan → decide → delete")
    print(f"  [i] ancestor is only fully deleted when ALL {len(sessions)} "
          f"accounts are empty")

    # one persistent uploader per account
    scanners = []
    for n, ch, tk in sessions:
        set_active_account(n)
        scanners.append((n, TeraBoxUploader(ch, tk)))

    for parent in parents:
        await asyncio.sleep(1.5)

        per_account = []   # (n, state, data)
        # state ∈ {empty, absent, nonempty, error}
        for n, scanner in scanners:
            set_active_account(n)
            try:
                r = scanner.list_dir(parent)
            except Exception as e:
                per_account.append((n, "error", f"exception: {e}"))
                continue
            errno = r.get("errno")
            if errno == 0:
                items = r.get("list", [])
                per_account.append(
                    (n, "nonempty" if items else "empty", items)
                )
            elif isinstance(errno, int) and errno < 0:
                per_account.append((n, "absent", None))
            else:
                per_account.append((n, "error", f"errno={errno}"))

        states = {n: st for n, st, _ in per_account}
        empties = [n for n, st, _ in per_account if st in ("empty", "absent")]
        nonempties = [(n, d) for n, st, d in per_account
                      if st == "nonempty"]
        errors = [(n, d) for n, st, d in per_account if st == "error"]

        # ── any hard error → bail ──
        if errors:
            print(f"  ⚠️  {parent}: some accounts returned errors — "
                  f"stopping cascade")
            for n, e in errors:
                print(f"       account {n}: {e}")
            return

        # ── mixed: some empty, some not ──
        if nonempties:
            print(f"  ✋ {parent} — mixed state across accounts:")
            for n, st, d in per_account:
                if st == "nonempty":
                    print(f"       account {n}: {len(d)} item(s)")
                    for it in d[:10]:
                        name = it.get("server_filename", "?")
                        isdir = it.get("isdir") == 1
                        kind = "📁" if isdir else "📄"
                        print(f"         {kind} {name}")
                    if len(d) > 10:
                        print(f"         ... and {len(d) - 10} more")
                else:
                    print(f"       account {n}: {st}")

            if empties:
                if ask_yes_no(
                    f"delete {parent} only on the empty account(s) "
                    f"{empties}?", default_yes=False,
                ):
                    for n in empties:
                        set_active_account(n)
                        up = next(u for (nn, u) in scanners if nn == n)
                        ok, resp = up.delete_remote_folder(parent)
                        if ok:
                            print(f"  🗑  account {n}: deleted {parent} (API)")
                            continue
                        errno = (resp.get("errno")
                                 if isinstance(resp, dict) else None)
                        print(f"  ⚠️  account {n}: {parent} API delete "
                              f"failed (errno={errno})")
                        if errno == 450016:
                            ui_ok = await delete_folder_via_ui(n, parent)
                            if ui_ok:
                                print(f"  🗑  account {n}: deleted "
                                      f"{parent} (UI)")
                            else:
                                print(f"  ❌ account {n}: UI delete failed")
            print(f"  [i] cascade stopped at {parent} — "
                  f"non-empty accounts preserved")
            return

        # ── all empty/absent → offer to delete on all ──
        all_summary = ", ".join(f"{n}:{states[n]}" for n, _, _ in per_account)
        print(f"  ✓ {parent} is empty/absent on all accounts ({all_summary})")
        if not ask_yes_no(f"delete empty parent {parent} on all accounts?",
                         default_yes=False):
            print(f"  [i] cascade stopped by user at {parent}")
            return

        for n, up in scanners:
            set_active_account(n)
            ok, resp = up.delete_remote_folder(parent)
            if ok:
                print(f"  🗑  account {n}: deleted {parent} (API)")
                continue
            errno = resp.get("errno") if isinstance(resp, dict) else None
            print(f"  ⚠️  account {n}: {parent} API delete failed "
                  f"(errno={errno})")
            if errno == 450016:
                ui_ok = await delete_folder_via_ui(n, parent)
                if ui_ok:
                    print(f"  🗑  account {n}: deleted {parent} (UI)")
                else:
                    print(f"  ❌ account {n}: {parent} UI delete failed — "
                          f"stopping cascade")
                    return

    print("  ✅ cascade complete")


async def ghost_cleanup_only(ghost_folder: str):
    """Skip download/decrypt — just delete shards + folder from TeraBox.

    For when the shards were already downloaded and decrypted locally but
    the remote cleanup was skipped or failed.
    """
    ghost_folder = "/" + ghost_folder.strip("/")
    folder_basename = ghost_folder.rstrip("/").split("/")[-1]
    if not folder_basename:
        print("  ❌ invalid ghost folder")
        return
    if "<" in folder_basename or ">" in folder_basename:
        print(f"  ❌ folder basename {folder_basename!r} still contains "
              f"angle brackets — replace <ghost_id> with the actual id.")
        return
    ghost_id = folder_basename
    _start_job(f"Cleanup · {ghost_id[:12]}…")

    print("=" * 62)
    print("  GHOST CLEANUP  —  no download, no decrypt")
    print("=" * 62)
    print(f"  Ghost folder: {ghost_folder}")
    print(f"  Ghost id:     {ghost_id}")
    print()
    print(f"  Expected shards (one per account):")
    for i in range(GHOST_SHARD_COUNT):
        print(f"    account {i + 1}: "
              f"{shard_filename(ghost_id, i + 1, GHOST_SHARD_COUNT)}")
    print()

    delete_shards = ask_yes_no("delete the 3 shards from TeraBox?",
                               default_yes=True)
    delete_folder = ask_yes_no("also delete the ghost folder?",
                               default_yes=True)
    cascade_parents = ask_yes_no(
        "after that, cascade-delete empty parent folders above it?",
        default_yes=True,
    )

    if not delete_shards and not delete_folder and not cascade_parents:
        print("  [i] nothing to do.")
        notify_job_end("no-op", "nothing selected")
        return

    print("\n[*] sniffing all accounts ...")
    sessions = await _sniff_all_accounts()
    if sessions is None:
        print("  ❌ sniff aborted — cannot delete")
        return

    if delete_shards:
        for idx, (n, cookie_header, tokens) in enumerate(sessions):
            set_active_account(n)
            uploader = TeraBoxUploader(cookie_header, tokens)
            shard_name = shard_filename(ghost_id, idx + 1, GHOST_SHARD_COUNT)

            # check-before-delete: only touch accounts where it exists
            present = _item_present(uploader, ghost_folder, shard_name)
            if present is False:
                print(f"  [skip] account {n}: {shard_name} not present")
                continue
            if present is None:
                print(f"  ⚠️  account {n}: cannot verify {shard_name} — "
                      f"skipping to be safe")
                continue

            ok, resp = uploader.delete_remote_file(ghost_folder, shard_name)
            if ok:
                print(f"  🗑  account {n}: deleted {shard_name} (API)")
                continue
            errno = resp.get("errno") if isinstance(resp, dict) else None
            print(f"  ⚠️  account {n}: shard API delete failed "
                  f"(errno={errno})")
            if errno == 450016:
                print(f"  [i] errno 450016 — trying UI delete ...")
                ui_ok = await delete_via_ui(n, ghost_folder, shard_name)
                if ui_ok:
                    print(f"  🗑  account {n}: deleted {shard_name} (UI)")
                else:
                    print(f"  ❌ account {n}: shard UI delete also failed")

    if delete_folder:
        folder_basename_local = ghost_folder.rstrip("/").split("/")[-1]
        parent_local = "/".join(ghost_folder.rstrip("/").split("/")[:-1])
        for idx, (n, cookie_header, tokens) in enumerate(sessions):
            set_active_account(n)
            uploader = TeraBoxUploader(cookie_header, tokens)

            present = _item_present(uploader, parent_local,
                                   folder_basename_local)
            if present is False:
                print(f"  [skip] account {n}: {ghost_folder} "
                      f"already absent")
                continue
            if present is None:
                print(f"  ⚠️  account {n}: cannot verify {ghost_folder} — "
                      f"skipping to be safe")
                continue

            ok, resp = uploader.delete_remote_folder(ghost_folder)
            if ok:
                print(f"  🗑  account {n}: deleted folder "
                      f"{ghost_folder} (API)")
                continue
            errno = resp.get("errno") if isinstance(resp, dict) else None
            print(f"  ⚠️  account {n}: folder API delete failed "
                  f"(errno={errno})")
            if errno == 450016:
                print(f"  [i] errno 450016 — trying UI folder delete ...")
                ui_ok = await delete_folder_via_ui(n, ghost_folder)
                if ui_ok:
                    print(f"  🗑  account {n}: deleted folder "
                          f"{ghost_folder} (UI)")
                else:
                    print(f"  ❌ account {n}: folder UI delete also failed")

    if cascade_parents:
        await cascade_empty_parents(sessions, ghost_folder, stop_at="/")

    print("\n  cleanup done.")
    notify_job_end("complete",
                   f"shards={delete_shards} folder={delete_folder} "
                   f"cascade={cascade_parents}")


# ============================================================
# upload prompts + flows (single-account)
# ============================================================
def prompt_inputs():
    print("=" * 62)
    print("  Encrypted Video Scrapper → TeraBox")
    print("=" * 62)
    url = input("Show URL: ").strip()
    if not url:
        sys.exit("no URL")
    show = input("Show name (for filename): ").strip() or "video"
    while True:
        v = input("Season number: ").strip()
        if v.isdigit():
            season = int(v)
            break
        print("  enter a number")
    spec = input("Episodes (e.g. 1, 1-20, 1-5,8,10-12) [1]: ").strip() or "1"
    episodes = parse_episode_range(spec)
    if not episodes:
        sys.exit("bad episode list")
    headless = input("Headless capture browser? (y/n) [y]: ").strip().lower() != "n"
    wait_raw = input("Seconds to wait for player [25]: ").strip()
    wait_time = int(wait_raw) if wait_raw.isdigit() else 25
    return url, show, season, episodes, headless, wait_time


def prompt_movie_inputs():
    print("=" * 62)
    print("  Encrypted Movie Scrapper → TeraBox")
    print("=" * 62)
    url = input("Movie URL: ").strip()
    if not url:
        sys.exit("no URL")
    title = input("Movie title (for filename): ").strip() or "movie"
    year_raw = input("Year (optional, e.g. 1999): ").strip()
    year = year_raw if year_raw else ""
    headless = input("Headless capture browser? (y/n) [y]: ").strip().lower() != "n"
    wait_raw = input("Seconds to wait for player [45]: ").strip()
    wait_time = int(wait_raw) if wait_raw.isdigit() else 45
    return url, title, year, headless, wait_time


async def run_upload(
    url, show, season, episodes, headless, wait_time,
    remote_override="", encrypt=True, master=None,
):
    global uploaded_md5s
    uploaded_md5s = {}
    _start_job(f"TV · {sanitize(show)} S{int(season):02d}")

    print(f"\n[*] account: {ACTIVE_ACCOUNT}")
    print(f"[*] {len(episodes)} episode(s) queued: {episodes}")
    print(f"[*] encryption: {'ON (AES-256-GCM)' if encrypt else 'OFF'}")

    cookie_header, tokens = await terabox_sniff()
    if not tokens.get("jsToken"):
        raise RuntimeError("no jsToken captured")

    uploader = TeraBoxUploader(cookie_header, tokens)

    if encrypt:
        suggested = remote_override or (
            f"{DEFAULT_REMOTE_ROOT}/encrypted/{sanitize(show)}"
        )
    else:
        suggested = remote_override or (
            f"{DEFAULT_REMOTE_ROOT}/{sanitize(show)}/Season_{season:02d}"
        )
    remote_dir = pick_remote_folder(uploader, suggested=suggested)

    if not ask_yes_no(f"\nstart {len(episodes)} ep(s) → {remote_dir}?", default_yes=True):
        return

    ok_list, skip_list, fail_list = [], [], []
    for i, ep in enumerate(episodes, 1):
        print(f"\n[{i}/{len(episodes)}]")
        ok, reason = await handle_episode(
            uploader, url, show, season, ep, remote_dir,
            wait_time, headless, encrypt=encrypt, master=master,
            source_url=url,
        )
        tag = f"S{season:02d}E{ep:02d}"
        if reason == "skipped":
            skip_list.append(tag)
        elif ok:
            ok_list.append(tag)
        else:
            fail_list.append(tag)

    print("\n" + "=" * 62)
    print("  DONE")
    print("=" * 62)
    print(f"  account:  {ACTIVE_ACCOUNT}")
    print(f"  uploaded: {len(ok_list)}   {ok_list}")
    print(f"  skipped:  {len(skip_list)}   {skip_list}")
    print(f"  failed:   {len(fail_list)}   {fail_list}")
    if encrypt:
        print()
        print("  reminder: keep your passphrase safe. Files cannot be")
        print("  recovered without it.")

    if fail_list and not ok_list:
        _status = "failed"
    elif fail_list:
        _status = "partial"
    else:
        _status = "complete"
    notify_job_end(_status,
                   f"↑{len(ok_list)} ↷{len(skip_list)} ✗{len(fail_list)}")


async def run_upload_movie(
    url, title, year, headless, wait_time,
    remote_override="", master=None,
):
    tag = sanitize(title)
    if year:
        tag = f"{tag}_{year}"

    _start_job(f"Movie · {tag}")

    print(f"\n[*] account: {ACTIVE_ACCOUNT}")
    print(f"[*] Movie: {tag}")
    print(f"[*] encryption: ON (AES-256-GCM)")

    cookie_header, tokens = await terabox_sniff()
    if not tokens.get("jsToken"):
        raise RuntimeError("no jsToken captured")

    uploader = TeraBoxUploader(cookie_header, tokens)

    suggested = remote_override or f"{DEFAULT_REMOTE_ROOT}/encrypted/Movies"
    remote_dir = pick_remote_folder(uploader, suggested=suggested)

    if not ask_yes_no(f"\nstart movie → {remote_dir}?", default_yes=True):
        return

    ok, reason = await handle_movie(
        uploader, url, title, year, remote_dir,
        wait_time, headless, master,
    )

    print("\n" + "=" * 62)
    print("  DONE")
    print("=" * 62)
    print(f"  account: {ACTIVE_ACCOUNT}")
    if reason == "skipped":
        print(f"  [skip] already on TeraBox: {tag}")
    elif ok:
        print(f"  ✅ uploaded: {tag}")
    else:
        print(f"  ❌ failed: {reason}")
    print()
    print("  reminder: keep your passphrase safe. Files cannot be")
    print("  recovered without it.")

    if reason == "skipped":
        notify_job_end("no-op", "already on TeraBox")
    elif ok:
        notify_job_end("complete", tag)
    else:
        notify_job_end("failed", f"reason={reason}")


# ============================================================
# decrypt-only flow
# ============================================================
async def decrypt_main(paths: list[str], out_dir: Path | None):
    print("=" * 62)
    print("  DECRYPT MODE")
    print("=" * 62)
    passphrase = prompt_passphrase(confirm=False)

    ok, fail = 0, 0
    for p in paths:
        target = Path(p).expanduser()
        if target.is_dir():
            for f in sorted(target.glob("*.bin")):
                if decrypt_one(f, passphrase, out_dir):
                    ok += 1
                else:
                    fail += 1
        elif target.is_file():
            if decrypt_one(target, passphrase, out_dir):
                ok += 1
            else:
                fail += 1
        else:
            print(f"  ⚠️  not found: {target}")
            fail += 1

    print(f"\n  decrypted: {ok}   failed: {fail}")


# ============================================================
# neon-noir boot banner
# ============================================================
def _render_intro_banner(animated=True):
    C  = "\033[96m"      # cyan
    M  = "\033[95m"      # magenta
    Y  = "\033[93m"      # yellow
    G  = "\033[92m"      # green
    R  = "\033[91m"      # red
    BL = "\033[94m"      # blue
    D  = "\033[90m"      # dim
    B  = "\033[1m"       # bold
    X  = "\033[0m"       # reset
    BW = "\033[1;97m"    # bright bold white

    W = 60

    RAINBOW = [R, Y, G, C, BL, M]
    GLYPHS  = "▓▒░#@%&$"

    _ANSI = re.compile(r"\033\[[0-9;]*m")

    # ---------- text utilities ----------
    def _wide(ch):
        o = ord(ch)
        return (
            0x1100 <= o <= 0x115F or
            0x2E80 <= o <= 0xA4CF or
            0xAC00 <= o <= 0xD7A3 or
            0xF900 <= o <= 0xFAFF or
            0xFE30 <= o <= 0xFE4F or
            0xFF00 <= o <= 0xFF60 or
            0xFFE0 <= o <= 0xFFE6 or
            0x1F300 <= o <= 0x1FAFF or
            0x2600  <= o <= 0x27BF
        )

    def vis(s):
        return sum(2 if _wide(c) else 1 for c in _ANSI.sub("", s))

    def fit(s, width, align="left"):
        gap = max(0, width - vis(s))
        if align == "center":
            l = gap // 2
            return " " * l + s + " " * (gap - l)
        return s + " " * gap

    def rainbow(s, glitch=False):
        out = []
        i = 0
        for ch in s:
            if ch == " ":
                out.append(ch)
                continue
            if glitch and random.random() < 0.14:
                out.append(f"{R}{B}{random.choice(GLYPHS)}{X}")
            else:
                out.append(f"{RAINBOW[i % len(RAINBOW)]}{B}{ch}{X}")
            i += 1
        return "".join(out)

    # ---------- frame pieces (all borders magenta) ----------
    top     = f"{M}╔{'═' * W}╗{X}"
    mid     = f"{M}╠{'═' * W}╣{X}"
    bottom  = f"{M}╚{'═' * W}╝{X}"
    blank   = f"{M}║{X}" + " " * W + f"{M}║{X}"

    divider = f"{BW}{'═' * (W - 8)}{X}"

    # ---------- content lines ----------
    title_plain = "M A S Q   F L O W"
    tagline     = (
        f"{C}{B}SILENT PULL{X} {BW}{B}↔{X} {M}{B}DEADDROP{X}"
        f"   {D}│{X}   {G}{B}GHOST MULTI{X}"
    )
    status      = (
        f"{Y}{B}▸{X} {C}LINK:{X} {G}SECURE{X}"
        f"   {D}│{X}   {C}PROTOCOL:{X} {M}{B}GHOST{X}"
    )

    def build_frame(title_mode="off"):
        if title_mode == "off":
            title = f"{D}{B}🎭  {title_plain}{X}"
        elif title_mode == "glitch":
            title = f"🎭  {rainbow(title_plain, glitch=True)}"
        else:
            title = f"🎭  {rainbow(title_plain)}"

        return [
            top,
            blank,
            f"{M}║{X}" + fit(title, W, "center") + f"{M}║{X}",
            f"{M}║{X}" + fit(divider, W, "center") + f"{M}║{X}",
            f"{M}║{X}" + fit(tagline, W, "center") + f"{M}║{X}",
            blank,
            mid,
            f"{M}║{X}" + fit(status, W, "center") + f"{M}║{X}",
            bottom,
        ]

    # ---------- render ----------
    if not animated or not sys.stdout.isatty():
        print()
        print("\n".join(build_frame("final")))
        print()
        return

    def repaint(lines):
        sys.stdout.write(f"\033[{len(lines)}A")
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    print("\033[?25l", end="")
    try:
        print()
        shell = [f"{M}╔{'═' * W}╗{X}"] + [blank] * 7 + [f"{M}╚{'═' * W}╝{X}"]
        print("\n".join(shell))
        time.sleep(0.07)
        repaint([top] + [blank] * 7 + [bottom])
        time.sleep(0.07)

        repaint(build_frame("off"))
        time.sleep(0.09)

        repaint(build_frame("glitch"))
        time.sleep(0.07)

        repaint(build_frame("final"))
    finally:
        print("\033[?25h", end="")


# ============================================================
# interactive menu (sync)
# ============================================================
def _render_abort_notice(msg: str = "Check your credentials!") -> None:
    R = "\033[91m"   # red
    B = "\033[1m"    # bold
    D = "\033[90m"   # dim
    X = "\033[0m"
    W = 60

    print()
    print(f"  {R}{'─' * W}{X}")
    print(f"  {R}{B}▸ ABORT{X}  {R}{msg}{X}")
    print(f"  {R}{'─' * W}{X}")
    print()

def run_interactive_menu_sync():
    _render_intro_banner(animated=True)

    if not print_creds_diagnostic():
        _render_abort_notice()
        return None

    try:
        encrypt_choice = ask_yes_no(
            "Do you want to encrypt a video to TeraBox?", default_yes=True
        )
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        sys.exit(130)

    if encrypt_choice:
        _section("MODE")
        while True:
            try:
                mode = input(_ask_pick(
                    "mode",
                    [("1", "single account"),
                     ("2", "ghost"),
                     ("3", "ghost batch · whole season")],
                    default="1",
                )).strip() or "1"
            except (KeyboardInterrupt, EOFError):
                print("\nInterrupted.")
                sys.exit(130)
            if mode in ("1", "2", "3"):
                break
            _ask_error("enter 1, 2 or 3")

        if mode == "2":
            _section("TARGET")
            while True:
                try:
                    kind = input(_ask_pick(
                        "target",
                        [("1", "TV show"), ("2", "movie")],
                        default="1",
                    )).strip() or "1"
                except (KeyboardInterrupt, EOFError):
                    print("\nInterrupted.")
                    sys.exit(130)
                if kind in ("1", "2"):
                    break
                _ask_error("enter 1 or 2")

            if kind == "1":
                url, show, season, episodes, headless, wait_time = prompt_inputs()
                passphrase = prompt_passphrase(confirm=True)
                return ("upload_tv_ghost", url, show, season, episodes,
                        headless, wait_time, passphrase)
            else:
                url, title, year, headless, wait_time = prompt_movie_inputs()
                passphrase = prompt_passphrase(confirm=True)
                return ("upload_movie_ghost", url, title, year,
                        headless, wait_time, passphrase)

        if mode == "3":
            _section("GHOST BATCH")
            url, show, season, episodes, headless, wait_time = prompt_inputs()
            skip_existing = ask_yes_no(
                "skip already-uploaded episodes?", default_yes=True
            )
            passphrase = prompt_passphrase(confirm=True)
            return ("upload_tv_ghost_batch", url, show, season, episodes,
                    headless, wait_time, passphrase, skip_existing)

        account = prompt_account_choice()
        set_active_account(account)

        _section("TARGET")
        while True:
            try:
                kind = input(_ask_pick(
                    "target",
                    [("1", "TV show"), ("2", "movie")],
                    default="1",
                )).strip() or "1"
            except (KeyboardInterrupt, EOFError):
                print("\nInterrupted.")
                sys.exit(130)
            if kind in ("1", "2"):
                break
            _ask_error("enter 1 or 2")

        if kind == "1":
            url, show, season, episodes, headless, wait_time = prompt_inputs()
            passphrase = prompt_passphrase(confirm=True)
            return ("upload_tv", url, show, season, episodes,
                    headless, wait_time, passphrase)
        else:
            url, title, year, headless, wait_time = prompt_movie_inputs()
            passphrase = prompt_passphrase(confirm=True)
            return ("upload_movie", url, title, year,
                    headless, wait_time, passphrase)

    decrypt_choice = ask_yes_no(
        "Are you planning to decrypt a video from TeraBox to a folder?",
        default_yes=True,
    )
    if not decrypt_choice:
        print()
        print(f"  {_D}come on dude, make up your mind next time.{_X}")
        print()
        return None

    _section("RECONSTRUCT")
    while True:
        try:
            rkind = input(_ask_pick(
                "format",
                [("1", "single .bin"),
                 ("2", "ghost · 3 shards"),
                 ("3", "cleanup only · no download")],
                default="1",
            )).strip() or "1"
        except (KeyboardInterrupt, EOFError):
            print("\nInterrupted.")
            sys.exit(130)
        if rkind in ("1", "2", "3"):
            break
        _ask_error("enter 1, 2 or 3")

    if rkind == "3":
        folder = input(_ask_line(
            "ghost folder on TeraBox",
            "(cleanup only — shards already downloaded)",
        )).strip()
        if not folder:
            print(f"  {_D}no folder given.{_X}")
            return None
        return ("ghost_cleanup", folder)

    if rkind == "2":
        folder = input(_ask_line(
            "ghost folder on TeraBox",
            "(e.g. /_Rescue_Uploads/encrypted/Ghosts/<ghost_id>)",
        )).strip()
        if not folder:
            print(f"  {_D}no folder given.{_X}")
            return None
        out = input(_ask_line(
            "save folder",
            f"[{DEFAULT_DOWNLOAD_DIR}]",
        )).strip() or DEFAULT_DOWNLOAD_DIR
        return ("ghost_reconstruct", folder, out)

    download_first = ask_yes_no(
        "Do you want to download it from TeraBox first?", default_yes=True
    )

    if download_first:
        account = prompt_account_choice()
        set_active_account(account)
        url = input(_ask_line(
            "TeraBox URL",
            "(Enter for https://www.terabox.com/main)",
        )).strip() or "https://www.terabox.com/main"
        out = input(_ask_line(
            "save folder",
            f"[{DEFAULT_DOWNLOAD_DIR}]",
        )).strip() or DEFAULT_DOWNLOAD_DIR
        return ("download", url, out)

    p = input(_ask_line("path to .bin file or folder")).strip()
    if not p:
        print(f"  {_D}no path given.{_X}")
        return None
    out = input(_ask_line("output folder", "[same as .bin]")).strip()
    return ("decrypt_local", p, out or None)

async def dispatch_interactive(decision):
    global master_key
    if decision is None:
        return

    mode = decision[0]

    if mode == "upload_tv":
        _, url, show, season, episodes, headless, wait_time, passphrase = decision
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase
        await run_upload(
            url, show, season, episodes, headless, wait_time,
            encrypt=True, master=master_key,
        )

    elif mode == "upload_movie":
        _, url, title, year, headless, wait_time, passphrase = decision
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase
        await run_upload_movie(
            url, title, year, headless, wait_time, master=master_key,
        )

    elif mode == "upload_tv_ghost":
        _, url, show, season, episodes, headless, wait_time, passphrase = decision
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase
        await run_upload_ghost_tv(
            url, show, season, episodes, headless, wait_time, master_key,
        )

    elif mode == "upload_movie_ghost":
        _, url, title, year, headless, wait_time, passphrase = decision
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase
        await run_upload_ghost_movie(
            url, title, year, headless, wait_time, master_key,
        )

    elif mode == "upload_tv_ghost_batch":
        (_, url, show, season, episodes, headless, wait_time,
         passphrase, skip_existing) = decision
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase
        await run_upload_ghost_tv_batch(
            url, show, season, episodes, headless, wait_time, master_key,
            skip_existing=skip_existing,
        )

    elif mode == "download":
        _, url, out = decision
        await download_mode(
            start_url=url,
            save_dir=Path(out).expanduser(),
            threads=16,
            do_decrypt=True,
            passphrase="",
        )

    elif mode == "ghost_reconstruct":
        _, folder, out = decision
        await ghost_reconstruct(folder, Path(out).expanduser(), threads=16)

    elif mode == "ghost_cleanup":
        _, folder = decision
        await ghost_cleanup_only(folder)

    elif mode == "decrypt_local":
        _, p, out = decision
        out_dir = Path(out).expanduser() if out else None
        await decrypt_main([p], out_dir)


# ============================================================
# CLI
# ============================================================
def build_parser():
    p = argparse.ArgumentParser(
        description="Encrypted lookmovie2 → TeraBox + download + decrypt "
                    "(multi-account, ghost-capable).",
    )
    p.add_argument("--account", type=int, choices=[1, 2, 3], default=1,
                   help="which TeraBox account to use (single-account modes)")
    p.add_argument("--ghost", action="store_true",
                   help="ghost mode — shard across all 3 accounts")
    p.add_argument("--ghost-batch", action="store_true",
                   help="ghost batch mode — whole season, skip-existing, "
                        "continue-on-failure")
    p.add_argument("--notify-test", action="store_true",
                   help="fire a test notification and exit")

    p.add_argument("--url")
    p.add_argument("--show")
    p.add_argument("--season", type=int)
    p.add_argument("--episodes", help="e.g. '1' or '1-20'")
    p.add_argument("--wait", type=int, default=25)
    p.add_argument("--headless", action="store_true")
    p.add_argument("--remote", default="")
    p.add_argument("--no-encrypt", action="store_true")

    p.add_argument("--movie", action="store_true")
    p.add_argument("--title", default="")
    p.add_argument("--year", default="")

    p.add_argument("--download", metavar="URL")
    p.add_argument("--ghost-reconstruct", metavar="FOLDER",
                   help="reconstruct a ghost from the given TeraBox folder")
    p.add_argument("--ghost-cleanup", metavar="FOLDER",
                   help="cleanup only — delete shards + folder, no download")
    p.add_argument("--out", default="")
    p.add_argument("--threads", type=int, default=16)
    p.add_argument("--no-decrypt", action="store_true")
    p.add_argument("--decrypt", nargs="+", metavar="PATH")
    return p


async def main_async():
    global master_key
    args = build_parser().parse_args()

    if args.notify_test:
        notify(
            "MASQ FLOW · test",
            f"pipeline OK · mode={_notify_mode()} · "
            f"webhook={'set' if _discord_webhook() else 'unset'}",
            level="success",
        )
        return

    if args.ghost_reconstruct:
        out_dir = (
            Path(args.out).expanduser() if args.out else Path(DEFAULT_DOWNLOAD_DIR)
        )
        threads = max(1, min(args.threads, 16))
        await ghost_reconstruct(args.ghost_reconstruct, out_dir, threads=threads)
        return

    if args.ghost_cleanup:
        await ghost_cleanup_only(args.ghost_cleanup)
        return

    if args.download:
        set_active_account(args.account)
        out_dir = (
            Path(args.out).expanduser() if args.out else Path(DEFAULT_DOWNLOAD_DIR)
        )
        threads = max(1, min(args.threads, 16))
        await download_mode(
            start_url=args.download,
            save_dir=out_dir,
            threads=threads,
            do_decrypt=not args.no_decrypt,
            passphrase="",
        )
        return

    if args.decrypt:
        out_dir = Path(args.out).expanduser() if args.out else None
        await decrypt_main(args.decrypt, out_dir)
        return

    if args.url and args.show and args.season and args.episodes:
        episodes = parse_episode_range(args.episodes)
        headless, wait_time = args.headless, args.wait
        passphrase = prompt_passphrase(confirm=True)
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase

        if args.ghost_batch:
            await run_upload_ghost_tv_batch(
                args.url, args.show, args.season, episodes,
                headless, wait_time, master_key, skip_existing=True,
            )
        elif args.ghost:
            await run_upload_ghost_tv(
                args.url, args.show, args.season, episodes,
                headless, wait_time, master_key,
            )
        else:
            set_active_account(args.account)
            await run_upload(
                args.url, args.show, args.season, episodes,
                headless, wait_time,
                remote_override=args.remote,
                encrypt=True, master=master_key,
            )
        return

    if args.movie and args.url and args.title:
        headless = args.headless
        wait_time = args.wait if args.wait != 25 else 45
        passphrase = prompt_passphrase(confirm=True)
        print("  [*] deriving master key (PBKDF2, ~1s) ...")
        master_key = derive_master(passphrase)
        del passphrase

        if args.ghost:
            await run_upload_ghost_movie(
                args.url, args.title, args.year,
                headless, wait_time, master_key,
            )
        else:
            set_active_account(args.account)
            await run_upload_movie(
                args.url, args.title, args.year,
                headless, wait_time,
                remote_override=args.remote,
                master=master_key,
            )
        return

    raise SystemExit("no CLI arguments provided")


def main():
    try:
        args = build_parser().parse_args()

        if args.notify_test:
            mode = _notify_mode()
            webhook = _discord_webhook()
            verbose = _notify_verbose()
            print()
            print("  ── NOTIFY DIAGNOSTIC ──────────────────────────────")
            print(f"  mode:      {mode}")
            print(f"  verbose:   {verbose}")
            print(f"  webhook:   {'set (' + str(len(webhook)) + ' chars)' if webhook else 'unset'}")
            print(f"  platform:  {sys.platform}")
            print()
            print("  → probing raw osascript ...")
            try:
                probe = subprocess.run(
                    ["osascript", "-e",
                     'display notification "raw probe from GL_dual_accounts" '
                     'with title "MASQ FLOW · probe"'],
                    capture_output=True, timeout=5, text=True,
                )
                print(f"     osascript rc={probe.returncode}")
                if probe.stderr.strip():
                    print(f"     stderr: {probe.stderr.strip()}")
                if probe.returncode == 0 and not probe.stderr.strip():
                    print("     (rc=0 — if no banner appeared, macOS is")
                    print("      silently dropping it: check Terminal.app")
                    print("      notification permissions + Focus mode)")
            except Exception as e:
                print(f"     osascript probe failed: {e}")
            print()
            print(f"  → firing notify() in {mode} mode ...")
            notify(
                "MASQ FLOW · test",
                f"pipeline OK · mode={mode} · "
                f"webhook={'set' if webhook else 'unset'}",
                level="success",
            )
            print(f"  → done")
            return

        has_cli = bool(
            args.download
            or args.decrypt
            or args.ghost_reconstruct
            or args.ghost_cleanup
            or (args.url and args.show and args.season and args.episodes)
            or (args.movie and args.url and args.title)
        )
        if has_cli:
            asyncio.run(main_async())
            return

        decision = run_interactive_menu_sync()
        if decision is None:
            return
        asyncio.run(dispatch_interactive(decision))

    except KeyboardInterrupt:
        notify_job_end("aborted", "Ctrl-C")
        print("\nInterrupted.")
        sys.exit(130)
    except SystemExit:
        raise
    except BaseException as e:
        notify_job_end("failed", f"{type(e).__name__}: {e}")
        raise


if __name__ == "__main__":
    main()
