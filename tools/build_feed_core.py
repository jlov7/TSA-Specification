#!/usr/bin/env python3
"""
build_feed.py - TSA Feed Generator

Generates a TSA advisory feed index from a directory of advisory files.
The feed includes canonical hashes for integrity verification.

Usage:
    python3 build_feed.py advisories/ --output feeds/feed.json
    python3 build_feed.py advisories/ --base-url https://tsa.mcp.security/advisories

Version: 1.0.0
License: Apache-2.0
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

# Import canonicalize
try:
    from tools.tsactl import canonicalize, compute_canonical_hash
except ImportError:
    try:
        from tsactl import canonicalize, compute_canonical_hash
    except ImportError:
        # Inline for standalone use
        def canonicalize(obj):
            def _utf16_key(value: str) -> tuple:
                encoded = value.encode("utf-16-be")
                return tuple((encoded[i] << 8) | encoded[i + 1] for i in range(0, len(encoded), 2))

            if obj is None:
                return "null"
            elif isinstance(obj, bool):
                return "true" if obj else "false"
            elif isinstance(obj, int):
                return str(obj)
            elif isinstance(obj, float):
                if obj != obj:
                    raise ValueError("NaN not allowed in canonical JSON")
                if obj == float("inf") or obj == float("-inf"):
                    raise ValueError("Infinity not allowed in canonical JSON")
                if obj == int(obj):
                    return str(int(obj))
                s = repr(obj)
                if "." in s and "e" not in s.lower():
                    s = s.rstrip("0")
                    if s.endswith("."):
                        s += "0"
                return s
            elif isinstance(obj, str):
                return json.dumps(obj, ensure_ascii=False)
            elif isinstance(obj, list):
                return "[" + ",".join(canonicalize(i) for i in obj) + "]"
            elif isinstance(obj, dict):
                items = [
                    f"{canonicalize(k)}:{canonicalize(obj[k])}"
                    for k in sorted(obj.keys(), key=_utf16_key)
                ]
                return "{" + ",".join(items) + "}"
            raise TypeError(f"Cannot canonicalize: {type(obj)}")

        def compute_canonical_hash(doc, exclude_signature=True):
            d = {k: v for k, v in doc.items() if not (exclude_signature and k == "signature")}
            return "sha256:" + hashlib.sha256(canonicalize(d).encode("utf-8")).hexdigest()


def load_advisory(path: Path) -> Dict:
    """Load an advisory from a JSON file."""
    with open(path, "r") as f:  # pragma: no mutate
        return json.load(f)


def build_feed(advisory_dir: Path, base_url: str = None, inline: bool = False) -> Dict:
    """
    Build a TSA feed from a directory of advisories.

    Args:
        advisory_dir: Directory containing .tsa.json files
        base_url: Base URL for advisory references (if not inline)
        inline: If True, embed full advisories in feed

    Returns:
        Feed dictionary
    """
    advisories = []

    # Find all .tsa.json files
    for path in sorted(advisory_dir.glob("*.tsa.json")):
        try:
            advisory = load_advisory(path)
            canonical_hash = compute_canonical_hash(advisory)

            entry = {
                "id": advisory.get("id"),
                "uri": path.name,  # Will be overwritten below if base_url provided
                "canonical_hash": canonical_hash,
                "title": advisory.get("title"),
                "modified": advisory.get("modified"),
            }

            severity = advisory.get("severity", {}).get("qualitative")
            if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}:
                entry["severity"] = severity

            # Extract CVE references
            cve_refs = []
            for ref in advisory.get("references", []):
                if ref.get("type") == "CVE" and ref.get("id"):
                    cve_refs.append(ref["id"])
            for rv in advisory.get("related_vulnerabilities", []):
                if rv.get("id") and rv["id"].startswith("CVE-"):
                    cve_refs.append(rv["id"])
            if cve_refs:
                entry["cve"] = sorted(set(cve_refs))  # Dedupe deterministically

            if inline:
                entry["advisory"] = advisory
            elif base_url:
                entry["uri"] = f"{base_url.rstrip('/')}/{path.name}"
            else:
                entry["uri"] = path.name

            advisories.append(entry)

        except Exception as e:
            print(f"Warning: Failed to process {path}: {e}", file=sys.stderr)

    # Sort by modified date (newest first)
    advisories.sort(key=lambda x: x.get("modified") or "", reverse=True)

    feed = {
        "feed_version": "1.0.0",
        "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "publisher": {
            "name": "MCP Security Working Group",
            "namespace": "https://github.com/mcp-security",
        },
        "advisories": advisories,
    }

    return feed
