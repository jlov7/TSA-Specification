#!/usr/bin/env python3
"""
osv_converter.py - TSA/OSV Format Converter

CLI wrapper for TSA/OSV conversions.
Core logic lives in tools/osv_converter_core.py.
"""

import argparse
import json
import sys
from pathlib import Path

import tools.osv_converter_core as _core


def __getattr__(name: str):
    return getattr(_core, name)


def main():
    parser = argparse.ArgumentParser(
        description="Convert between TSA and OSV vulnerability formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  osv_converter.py tsa-to-osv advisory.tsa.json
  osv_converter.py tsa-to-osv advisory.tsa.json -o advisory.osv.json
  osv_converter.py osv-to-tsa GHSA-xxxx.json --id TSA-2025-0001
        """,
    )

    parser.add_argument(
        "direction", choices=["tsa-to-osv", "osv-to-tsa"], help="Conversion direction"
    )
    parser.add_argument("input", type=Path, help="Input file")
    parser.add_argument("--output", "-o", type=Path, help="Output file (default: stdout)")
    parser.add_argument(
        "--id",
        dest="tsa_id",
        help="TSA advisory ID to use for osv-to-tsa (e.g., TSA-2025-0001)",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")

    args = parser.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    if args.direction == "tsa-to-osv":
        result = _core.tsa_to_osv(data)
    else:
        result = _core.osv_to_tsa(data, tsa_id=args.tsa_id)

    indent = 2 if args.pretty else None
    output = json.dumps(result, indent=indent)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"✓ Converted to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
