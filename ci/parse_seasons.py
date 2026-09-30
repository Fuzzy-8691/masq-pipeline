#!/usr/bin/env python3
"""Parse "1-25" or "1,3,5" into JSON: {"season": [1,2,...,25]}"""
import json, sys
spec = sys.argv[1] if len(sys.argv) > 1 else "1"
out = set()
for chunk in spec.split(","):
    chunk = chunk.strip()
    if not chunk:
        continue
    if "-" in chunk:
        a, b = chunk.split("-", 1)
        a, b = a.strip(), b.strip()
        if a.isdigit() and b.isdigit():
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            out.update(range(lo, hi + 1))
    elif chunk.isdigit():
        out.add(int(chunk))
print(json.dumps({"season": sorted(out)}))
