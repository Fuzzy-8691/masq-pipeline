#!/usr/bin/env python3
"""pipeline.py - boot the pipeline from the TeraBox-hosted pack.

Flow:
  1. read _pack_config.json
  2. if _cache/.ready missing:
       - HTTP fetch TeraBox /main -> extract jsToken + bdstoken
       - HTTP /api/list -> get pack dlink
       - curl download pack -> _cache/pipeline_pack.tar.zst
       - extract with tar --zstd -> _cache/
       - fix venv paths -> venv --upgrade
       - write _cache/.ready
  3. exec _cache/venv/bin/python _cache/Browser_dual_account_C.py "$@"
"""

import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

HERE   = Path(__file__).resolve().parent
CONFIG = HERE / "_pack_config.json"
CACHE  = HERE / "_cache"
MARKER = CACHE / ".ready"

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36")


def load_config():
    return json.loads(CONFIG.read_text())


def http_get(url, cookie_ndus, extra_headers=None):
    headers = {
        "User-Agent": UA,
        "Cookie": f"ndus={cookie_ndus}",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=45) as resp:
        return resp.read().decode("utf-8", errors="replace")


def extract_tokens(html):
    js_token = ""
    bd_token = ""

    # jsToken lives inside a URL-encoded JS snippet in the JSON
    m = re.search(r'"jsToken":"([^"]+)"', html)
    if m:
        decoded = urllib.parse.unquote(m.group(1))
        m2 = re.search(r'fn\("([A-Fa-f0-9]+)"\)', decoded)
        if m2:
            js_token = m2.group(1)

    # bdstoken is plain hex in JSON
    m = re.search(r'"bdstoken":"([A-Fa-f0-9]+)"', html)
    if m:
        bd_token = m.group(1)

    # last-resort: raw URL-encoded jsToken if JSON shape changed
    if not js_token:
        m = re.search(r'fn%28%22([A-Fa-f0-9]{30,})%22%29', html)
        if m:
            js_token = m.group(1)

    return js_token, bd_token


def api_get(path, params, cookie_ndus):
    qs = urllib.parse.urlencode(params)
    url = f"https://www.terabox.com{path}?{qs}"
    txt = http_get(url, cookie_ndus, {"Referer": "https://www.terabox.com/main",
                                       "X-Requested-With": "XMLHttpRequest"})
    return json.loads(txt)


def find_dlink(cookie_ndus, js_token, bd_token, remote_path):
    remote_dir  = os.path.dirname(remote_path) or "/"
    remote_name = os.path.basename(remote_path)

    base_params = {
        "app_id": "250528",
        "channel": "dubox",
        "clienttype": "0",
        "web": "1",
        "bdstoken": bd_token,
        "jsToken": js_token,
        "dir": remote_dir,
        "order": "time",
        "desc": "1",
        "showempty": "0",
        "page": "1",
        "num": "200",
    }

    # attempt 1: /api/list with dlink=1
    try:
        p = dict(base_params); p["dlink"] = "1"
        data = api_get("/api/list", p, cookie_ndus)
        if data.get("errno") == 0:
            for it in data.get("list", []):
                if it.get("server_filename") == remote_name:
                    for k in ("dlink", "downloadLink", "download_link"):
                        if it.get(k):
                            return it[k]
    except Exception as e:
        print(f"[i] /api/list?dlink=1 failed: {e}")

    # attempt 2: /api/filemetas
    try:
        p = dict(base_params)
        p["target"] = json.dumps([remote_path])
        p["dlink"] = "1"
        data = api_get("/api/filemetas", p, cookie_ndus)
        if data.get("errno") == 0:
            info = data.get("info") or []
            if isinstance(info, list):
                for it in info:
                    for k in ("dlink", "downloadLink", "download_link"):
                        if it.get(k):
                            return it[k]
    except Exception as e:
        print(f"[i] /api/filemetas failed: {e}")

    return None


def curl_download(url, dest, cookie_ndus):
    """Download with aria2c if available (16 parallel + resume), else curl."""
    dest.parent.mkdir(parents=True, exist_ok=True)

    aria = subprocess.run(["which", "aria2c"], capture_output=True).returncode == 0
    if aria:
        cmd = [
            "aria2c",
            f"--dir={dest.parent}",
            f"--out={dest.name}",
            "--split=16",
            "--max-connection-per-server=16",
            "--min-split-size=1M",
            "--continue=true",
            "--max-tries=10",
            "--retry-wait=3",
            "--timeout=60",
            "--console-log-level=warn",
            "--summary-interval=5",
            "--file-allocation=none",
            f"--header=Cookie: ndus={cookie_ndus}",
            f"--header=User-Agent: {UA}",
            url,
        ]
        print(f"[*] aria2c (16 connections, resumable) -> {dest.name} ...")
        r = subprocess.run(cmd)
        if r.returncode != 0:
            print(f"[!] aria2c exit {r.returncode}")
            return False
    else:
        cmd = [
            "curl", "-L", "--fail", "-C", "-", "-o", str(dest),
            "-H", f"Cookie: ndus={cookie_ndus}",
            "-H", f"User-Agent: {UA}",
            "--retry", "3", "--retry-delay", "5",
            "--max-time", "1800",
            url,
        ]
        print(f"[*] curl (with resume) -> {dest.name} ...")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[!] curl exit {r.returncode}: {r.stderr[:400]}")
            return False

    if not dest.exists() or dest.stat().st_size == 0:
        print("[!] downloaded file is empty")
        return False
    return True


def extract(tarball, dest):
    dest.mkdir(parents=True, exist_ok=True)
    print(f"[*] extracting with tar --zstd ...")
    r = subprocess.run(
        ["tar", "--zstd", "-xf", str(tarball), "-C", str(dest)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"[!] tar failed rc={r.returncode}: {r.stderr[:400]}")
        return False
    return True


def fix_venv(venv_dir):
    print(f"[*] repairing venv paths ...")
    r = subprocess.run(
        [sys.executable, "-m", "venv", "--upgrade", str(venv_dir)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"[!] venv --upgrade failed rc={r.returncode}: {r.stderr[:400]}")
        return False
    return True


def bootstrap(cfg):
    cookie = cfg["cookie_ndus"]
    remote = cfg["pack_remote_path"]

    print("[*] fetching TeraBox /main for tokens ...")
    html = http_get("https://www.terabox.com/main", cookie)
    js_token, bd_token = extract_tokens(html)
    if not js_token:
        print("[x] could not extract jsToken from /main")
        return 1
    print(f"    jsToken:  {js_token[:40]}...")
    print(f"    bdstoken: {bd_token[:40] if bd_token else '(none)'}")

    print("[*] resolving pack download link ...")
    dlink = find_dlink(cookie, js_token, bd_token, remote)
    if not dlink:
        print("[x] could not obtain dlink for the pack")
        return 1
    print(f"    dlink: {dlink[:80]}...")

    tarball = CACHE / "pipeline_pack.tar.zst"
    if not curl_download(dlink, tarball, cookie):
        return 1
    size = tarball.stat().st_size
    print(f"    downloaded: {size:,} bytes")

    if not extract(tarball, CACHE):
        return 1

    venv_dir = CACHE / "venv"
    if not venv_dir.exists():
        print(f"[x] venv missing after extract: {venv_dir}")
        return 1
    if not fix_venv(venv_dir):
        print("[!] venv repair failed — will try to run anyway")

    MARKER.write_text("ready\n")
    try:
        tarball.unlink()
    except Exception:
        pass
    return 0


def main():
    cfg = load_config()

    if not MARKER.exists():
        print("=" * 62)
        print("  PIPELINE BOOT")
        print("=" * 62)
        print(f"  config: {CONFIG.name}")
        print(f"  cache:  {CACHE}")
        print()
        rc = bootstrap(cfg)
        if rc != 0:
            print()
            print("[x] bootstrap failed")
            return rc
        print()
        print("[✓] cache is ready")

    venv_py = CACHE / "venv" / "bin" / "python"
    script  = CACHE / cfg["pipeline_script"]
    if not venv_py.exists():
        print(f"[x] venv python missing: {venv_py}")
        return 1
    if not script.exists():
        print(f"[x] pipeline script missing: {script}")
        return 1

    env = os.environ.copy()
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(CACHE / "patchright")
    env["PIPELINE_CACHE"] = str(CACHE)

    print(f"[*] exec: {venv_py.name} {script.name}")
    print()
    os.execve(str(venv_py), [str(venv_py), str(script)] + sys.argv[1:], env)


if __name__ == "__main__":
    sys.exit(main() or 0)
