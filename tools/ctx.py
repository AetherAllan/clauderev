#!/usr/bin/env python3
"""Fast bounded-context search over minified JS: literal or regex, no backtracking blowup."""
import os, re, sys

def main():
    root = sys.argv[1]
    pat = sys.argv[2]
    before = int(sys.argv[3]) if len(sys.argv) > 3 else 120
    after = int(sys.argv[4]) if len(sys.argv) > 4 else 200
    limit = int(sys.argv[5]) if len(sys.argv) > 5 else 40
    rx = re.compile(pat)
    shown = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith((".js", ".mjs", ".cjs", ".json", ".ts")):
                continue
            p = os.path.join(dirpath, fn)
            try:
                data = open(p, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if not rx.search(data):
                continue
            for m in rx.finditer(data):
                s = max(0, m.start() - before)
                e = min(len(data), m.end() + after)
                snippet = data[s:e].replace("\n", " ")
                print(f"--- {p} @{m.start()}")
                print(snippet)
                shown += 1
                if shown >= limit:
                    print(f"[stopped at {limit} matches]")
                    return
    if shown == 0:
        print("NO MATCH")

if __name__ == "__main__":
    main()
