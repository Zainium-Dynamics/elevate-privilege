#!/usr/bin/env python3
"""Print one dotted-path value from elevate_privilege.toml.

Usage: toml-get.py <a.b.c> [toml-file]   (default file: elevate_privilege.toml)

Single source of truth for the Makefile -- avoids hand-duplicating any
[paths]/[project] value that the Rust crates already read from this same
file via elevate-paths.
"""
import sys
import tomllib
from pathlib import Path

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: toml-get.py <a.b.c> [toml-file]", file=sys.stderr)
        return 2
    key = sys.argv[1]
    path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parent.parent / "elevate_privilege.toml"

    with path.open("rb") as f:
        data = tomllib.load(f)

    value = data
    for part in key.split("."):
        value = value[part]

    if isinstance(value, bool):
        print("true" if value else "false")
    else:
        print(value)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
