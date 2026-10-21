#!/usr/bin/env python3
"""Minimal offline ASAR extractor (no npm deps)."""
import json, os, struct, sys


def read_header(f):
    f.seek(0)
    a, b = struct.unpack("<II", f.read(8))
    if a != 4:
        raise SystemExit(f"unexpected header size0={a}")
    header_size = b
    pickle_size, = struct.unpack("<I", f.read(4))
    json_size, = struct.unpack("<I", f.read(4))
    raw = f.read(json_size)
    header = json.loads(raw.decode("utf-8"))
    base = 8 + pickle_size
    return header, base


def walk(node, prefix, base, f, out):
    for name, meta in node.get("files", {}).items():
        path = os.path.join(prefix, name)
        if "files" in meta:
            os.makedirs(os.path.join(out, path), exist_ok=True)
            walk(meta, path, base, f, out)
        else:
            dest = os.path.join(out, path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if meta.get("unpacked"):
                continue
            if "link" in meta:
                continue
            f.seek(base + int(meta["offset"]))
            data = f.read(int(meta["size"]))
            with open(dest, "wb") as g:
                g.write(data)


def main():
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    with open(src, "rb") as f:
        header, base = read_header(f)
        walk(header, "", base, f, out)
    print("extracted to", out)


if __name__ == "__main__":
    main()
