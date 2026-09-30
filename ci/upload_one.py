#!/usr/bin/env python3
"""Upload a single local file to a TeraBox account (for CI use)."""
import argparse
import asyncio
import os
import sys
from pathlib import Path

WS = Path(os.environ.get("PIPELINE_WS", os.getcwd()))
sys.path.insert(0, str(WS))

import Browser_dual_account_C as bda

CHUNK = 4 * 1024 * 1024


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("local_file")
    ap.add_argument("--account", type=int, required=True, choices=[1, 2, 3])
    ap.add_argument("--remote-dir", required=True)
    ap.add_argument("--skip-rapid", action="store_true")
    args = ap.parse_args()

    local = Path(args.local_file)
    if not local.exists():
        print(f"[x] local file not found: {local}")
        return 1
    size = local.stat().st_size
    print(f"[*] uploading {local.name} ({size:,} bytes)")
    print(f"    -> account {args.account} : {args.remote_dir}")

    bda.set_active_account(args.account)
    cookie_header, tokens = await bda.terabox_sniff()
    if not tokens.get("jsToken"):
        print("[x] no jsToken")
        return 1

    uploader = bda.TeraBoxUploader(cookie_header, tokens)
    bda.ensure_remote_path(uploader, args.remote_dir)

    chunks = []
    total = 0
    with local.open("rb") as f:
        while True:
            d = f.read(CHUNK)
            if not d:
                break
            chunks.append(d)
            total += len(d)
    print(f"    {len(chunks)} chunk(s), {total:,} bytes")

    try:
        result = uploader.upload_from_memory(
            local.name, chunks, total, args.remote_dir,
            skip_rapid=args.skip_rapid,
        )
    finally:
        chunks.clear()

    if result.get("errno") == 0:
        print(f"[OK] uploaded: {args.remote_dir}/{local.name}")
        return 0
    print(f"[x] upload errno={result.get('errno')}")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
