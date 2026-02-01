#!/usr/bin/env python3
"""
build_feed.py - TSA Feed Generator

CLI wrapper for TSA feed generation.
Core logic lives in tools/build_feed_core.py.
"""

import argparse
import json
import sys
from pathlib import Path

import tools.build_feed_core as _core


def __getattr__(name: str):
    return getattr(_core, name)


def main():
    parser = argparse.ArgumentParser(
        description="Build TSA advisory feed from directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  build_feed.py advisories/
  build_feed.py advisories/ --output feeds/feed.json
  build_feed.py advisories/ --base-url https://tsa.mcp.security/advisories
  build_feed.py advisories/ --inline
        """,
    )

    parser.add_argument("directory", type=Path, help="Directory containing .tsa.json files")
    parser.add_argument("--output", "-o", type=Path, help="Output file (default: stdout)")
    parser.add_argument("--base-url", help="Base URL for advisory URLs")
    parser.add_argument("--inline", action="store_true", help="Embed full advisories in feed")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    args = parser.parse_args()

    if not args.directory.is_dir():
        print(f"Error: {args.directory} is not a directory", file=sys.stderr)
        return 1

    feed = _core.build_feed(args.directory, args.base_url, args.inline)

    indent = 2 if args.pretty else None
    output = json.dumps(feed, indent=indent)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            f.write(output)
        print(f"✓ Feed written to {args.output} ({len(feed['advisories'])} advisories)")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
