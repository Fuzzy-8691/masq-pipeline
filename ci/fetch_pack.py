#!/usr/bin/env python3
"""Download pipeline_pack.tar.zst from TeraBox Account 3 and extract it."""
import json, os, re, subprocess
import urllib.parse, urllib.request
from pathlib import Path

NDUS        = os.environ["TB3_COOKIE"]
REMOTE_PATH = os.environ.get("PACK_REMOTE", "/pipeline/pipeline_pack.tar.zst")
OUT_DIR     = Path(os.environ.get("OUT_DIR", "/tmp/pack_extract"))
UA          = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/120.0.0.0 Safari/537.36")

def http_get(url, extra=None):
    h = {"User-Agent": UA, "Cookie": f"ndus={NDUS}",
         "Accept-Language": "en-US,en;q=0.9"}
    if extra:
        h.update(extra)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

def extract_tokens(html):
    js = bd = ""
    m = re.search(r'"jsToken":"([^"]+)"', html)
    if m:
        m2 = re.search(r'fn\("([A-Fa-f0-9]+)"\)', urllib.parse.unquote(m.group(1)))
        if m2:
            js = m2.group(1)
    m = re.search(r'"bdstoken":"([A-Fa-f0-9]+)"', html)
    if m:
        bd = m.group(1)
    return js, bd

def find_dlink(js, bd):
    remote_dir = os.path.dirname(REMOTE_PATH) or "/"
    remote_name = os.path.basename(REMOTE_PATH)
    params = {
        "app_id": "250528", "channel": "dubox", "clienttype": "0", "web": "1",
        "bdstoken": bd, "jsToken": js,
        "dir": remote_dir, "order": "time", "desc": "1",
        "showempty": "0", "page": "1", "num": "200", "dlink": "1",
    }
    url = "https://www.terabox.com/api/list?" + urllib.parse.urlencode(params)
    data = json.loads(http_get(url, {"Referer": "https://www.terabox.com/main",
                                     "X-Requested-With": "XMLHttpRequest"}))
    if data.get("errno") != 0:
        raise SystemExit(f"/api/list errno={data.get('errno')}")
    for it in data.get("list", []):
        if it.get("server_filename") == remote_name:
            for k in ("dlink", "downloadLink", "download_link"):
                if it.get(k):
                    return it[k]
    raise SystemExit(f"{remote_name} not found in {remote_dir}")

def main():
    print("[*] fetching tokens from TeraBox /main ...")
    html = http_get("https://www.terabox.com/main").decode("utf-8", errors="replace")
    js, bd = extract_tokens(html)
    if not js:
        raise SystemExit("no jsToken found")
    print(f"    jsToken: {js[:40]}...")

    print("[*] resolving pack dlink ...")
    dlink = find_dlink(js, bd)
    print(f"    dlink: {dlink[:80]}...")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tarball = OUT_DIR / "pipeline_pack.tar.zst"

    print("[*] downloading with aria2c ...")
    r = subprocess.run([
        "aria2c",
        f"--dir={OUT_DIR}", f"--out={tarball.name}",
        "--split=16", "--max-connection-per-server=16",
        "--min-split-size=1M", "--continue=true",
        "--max-tries=10", "--retry-wait=3", "--timeout=60",
        "--console-log-level=warn", "--summary-interval=15",
        "--file-allocation=none",
        f"--header=Cookie: ndus={NDUS}",
        f"--header=User-Agent: {UA}",
        dlink,
    ])
    if r.returncode != 0:
        raise SystemExit(f"aria2c failed rc={r.returncode}")

    print(f"    downloaded: {tarball.stat().st_size:,} bytes")

    print(f"[*] extracting to {OUT_DIR} ...")
    r = subprocess.run(["tar", "--zstd", "-xf", str(tarball), "-C", str(OUT_DIR)])
    if r.returncode != 0:
        raise SystemExit(f"tar failed rc={r.returncode}")

    print("[*] top-level contents:")
    for p in sorted(OUT_DIR.iterdir()):
        kind = "dir " if p.is_dir() else "file"
        print(f"    [{kind}] {p.name}")

    print("[*] patchright subfolders:")
    pr = OUT_DIR / "patchright"
    if pr.exists():
        for p in sorted(pr.iterdir()):
            print(f"    {p.name}")

    print("[*] done")

if __name__ == "__main__":
    main()
