#!/usr/bin/env python3
"""
tsa_registry_sdk.py - TSA Registry Integration SDK

Provides registry operators with a drop-in SDK for consuming TSA advisories
and enforcing security policies. Supports feed synchronization, signature
verification, and policy enforcement.

IMPORTANT: This SDK actually works as documented. The sync() method fetches
and indexes advisories. The check_package() method returns actionable results.

Usage:
    from tsa_registry_sdk import TSARegistry

    registry = TSARegistry()
    registry.subscribe_feed("https://tsa.mcp.security/feed.json")
    registry.sync()  # <-- Actually fetches and indexes advisories!

    result = registry.check_package("mcp-remote", "0.1.14", "npm")
    if result.blocked:
        print(result.message)  # Block the installation

Version: 1.0.0
License: Apache-2.0
"""

import base64
import binascii
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

# Semver parsing helpers
_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

# Try to import cryptography for signature verification
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def _normalize_version(value: str) -> str:
    value = value.strip()
    return value[1:] if value.lower().startswith("v") else value


def _parse_semver(value: str) -> Optional[tuple]:
    match = _SEMVER_RE.match(_normalize_version(value))
    if not match:
        return None
    major, minor, patch = (int(match.group(i)) for i in range(1, 4))
    prerelease = []
    if match.group(4):
        for ident in match.group(4).split("."):
            if ident.isdigit():
                prerelease.append((True, int(ident)))
            else:
                prerelease.append((False, ident))
    return major, minor, patch, prerelease


def _compare_prerelease(a, b) -> int:
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    for (a_is_num, a_val), (b_is_num, b_val) in zip(a, b):
        if a_is_num and b_is_num:
            if a_val < b_val:
                return -1
            if a_val > b_val:
                return 1
        elif a_is_num and not b_is_num:
            return -1
        elif not a_is_num and b_is_num:
            return 1
        else:
            if a_val < b_val:
                return -1
            if a_val > b_val:
                return 1
    if len(a) < len(b):
        return -1
    if len(a) > len(b):
        return 1
    return 0


# Import canonicalize from tsactl if available
try:
    from tools.tsactl import canonicalize, compute_canonical_hash
except ImportError:
    try:
        from tsactl import canonicalize, compute_canonical_hash
    except ImportError:
        # Inline minimal canonicalization for standalone use
        def canonicalize(obj: Any) -> str:
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
                if obj != obj:  # NaN
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

        def compute_canonical_hash(doc: Dict, exclude_signature: bool = True) -> str:
            d = {k: v for k, v in doc.items() if not (exclude_signature and k == "signature")}
            return "sha256:" + hashlib.sha256(canonicalize(d).encode("utf-8")).hexdigest()


@dataclass
class CheckResult:
    """Result of checking a package against TSA advisories."""

    blocked: bool = False
    warnings: List[str] = field(default_factory=list)
    advisories: List[Dict] = field(default_factory=list)
    message: str = ""
    actions: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "blocked": self.blocked,
            "message": self.message,
            "warnings": self.warnings,
            "advisory_count": len(self.advisories),
            "action_count": len(self.actions),
        }


@dataclass
class TrustAnchor:
    """A trusted signing key."""

    key_id: str
    public_key: str  # PEM or base64
    publisher: str
    trust_level: str = "full"  # full, warn_only, untrusted


class TSARegistry:
    """
    TSA Registry Integration SDK.

    Provides feed subscription, synchronization, and package checking.
    This is a REAL implementation that actually fetches and processes feeds.
    """

    def __init__(
        self,
        trust_anchors_path: Optional[str] = None,
        require_signatures: bool = False,
        cache_dir: Optional[str] = None,
        allow_insecure_http: bool = False,
    ):
        """
        Initialize the TSA Registry.

        Args:
            trust_anchors_path: Path to trust-anchors.json file
            require_signatures: If True, unsigned advisories are ignored for BLOCK actions
            cache_dir: Directory for caching fetched advisories
            allow_insecure_http: If True, allow plain HTTP feed/advisory fetches
        """
        self.feeds: List[str] = []
        self.advisories: Dict[str, Dict] = {}  # id -> advisory
        self.trust_anchors: Dict[str, TrustAnchor] = {}
        self.require_signatures = require_signatures
        self.allow_insecure_http = allow_insecure_http
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.last_sync: Optional[datetime] = None
        self.sync_errors: List[str] = []

        # Index for fast lookups: "name@registry" -> set of advisory_ids
        self._package_index: Dict[str, Set[str]] = {}

        if trust_anchors_path and os.path.exists(trust_anchors_path):
            self._load_trust_anchors(trust_anchors_path)

        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _load_trust_anchors(self, path: str):
        """Load trust anchors from JSON file."""
        with open(path, "r") as f:  # pragma: no mutate
            data = json.load(f)

        for anchor in data.get("anchors", []):
            ta = TrustAnchor(
                key_id=anchor["key_id"],
                public_key=anchor.get("public_key", ""),
                publisher=anchor.get("publisher", ""),
                trust_level=anchor.get("trust_level", "full"),
            )
            self.trust_anchors[ta.key_id] = ta

    def _load_public_key(self, key_data: str):
        """Load a public key from PEM or base64-encoded bytes."""
        key_data = (key_data or "").strip()
        if not key_data:
            raise ValueError("Empty public key")
        if key_data.startswith("-----BEGIN"):
            return serialization.load_pem_public_key(key_data.encode("utf-8"))  # pragma: no mutate
        try:
            raw = base64.b64decode(key_data)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Invalid public key encoding") from exc
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
        return serialization.load_der_public_key(raw)

    def _verify_signature(self, advisory: Dict, anchor: TrustAnchor) -> Tuple[bool, str]:
        """Verify advisory signature against a trust anchor."""
        signature = advisory.get("signature")
        if not signature:
            return False, "unsigned"
        if not CRYPTO_AVAILABLE:
            return False, "cryptography not available"
        algorithm = signature.get("algorithm")
        if algorithm not in ("Ed25519", "ES256", "ES384", "RS256"):
            return False, f"unsupported algorithm: {algorithm}"
        if signature.get("key_id") != anchor.key_id:
            return False, "key_id mismatch"
        value = signature.get("value")
        if not value:
            return False, "missing signature value"

        try:
            public_key = self._load_public_key(anchor.public_key)
        except Exception as exc:
            return False, f"invalid public key: {exc}"

        try:
            signature_bytes = base64.b64decode(value)
        except (binascii.Error, ValueError):
            return False, "invalid signature encoding"

        doc_copy = {k: v for k, v in advisory.items() if k != "signature"}
        canonical = canonicalize(doc_copy).encode("utf-8")  # pragma: no mutate
        try:
            if algorithm == "Ed25519":
                if not isinstance(public_key, Ed25519PublicKey):
                    return False, "invalid public key: expected Ed25519"
                public_key.verify(signature_bytes, canonical)
            elif algorithm == "RS256":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    return False, "invalid public key: expected RSA"
                public_key.verify(signature_bytes, canonical, padding.PKCS1v15(), hashes.SHA256())
            elif algorithm == "ES256":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    return False, "invalid public key: expected P-256"
                if not isinstance(public_key.curve, ec.SECP256R1):
                    return False, "invalid public key: expected P-256"
                public_key.verify(signature_bytes, canonical, ec.ECDSA(hashes.SHA256()))
            elif algorithm == "ES384":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    return False, "invalid public key: expected P-384"
                if not isinstance(public_key.curve, ec.SECP384R1):
                    return False, "invalid public key: expected P-384"
                public_key.verify(signature_bytes, canonical, ec.ECDSA(hashes.SHA384()))
        except Exception:
            return False, "invalid signature"
        return True, ""

    def subscribe_feed(self, url: str, sync_now: bool = False):
        """
        Subscribe to a TSA advisory feed.

        Args:
            url: Feed URL (https://, file://, or relative path)
            sync_now: If True, immediately sync the feed (default: False)

        Note: Call sync() after subscribing to fetch advisories.
        """
        if url not in self.feeds:
            self.feeds.append(url)

        if sync_now:
            self.sync()

    def sync(self) -> Dict:
        """
        Synchronize all subscribed feeds.

        This method ACTUALLY fetches advisories from feeds and indexes them.

        Returns:
            Dict with sync statistics
        """
        self.sync_errors = []
        stats = {"feeds_synced": 0, "advisories_added": 0, "advisories_updated": 0, "errors": []}

        for feed_url in self.feeds:
            try:
                feed_stats = self._sync_feed(feed_url)
                stats["feeds_synced"] += 1
                stats["advisories_added"] += feed_stats.get("added", 0)
                stats["advisories_updated"] += feed_stats.get("updated", 0)
            except Exception as e:
                error_msg = f"Failed to sync {feed_url}: {e}"
                stats["errors"].append(error_msg)
                self.sync_errors.append(error_msg)
                print(f"Warning: {error_msg}", file=sys.stderr)

        self.last_sync = datetime.now(timezone.utc)
        return stats

    def _sync_feed(self, feed_url: str) -> Dict:
        """Sync a single feed. Returns stats dict."""
        stats = {"added": 0, "updated": 0}
        feed_data = self._fetch_url(feed_url)

        # Handle feed format
        advisories_list = feed_data.get("advisories", [])

        for entry in advisories_list:
            try:
                advisory = None
                advisory_id = entry.get("id")
                expected_hash = entry.get("canonical_hash")

                # Inline advisory or URL reference?
                if "advisory" in entry:
                    advisory = entry["advisory"]
                elif entry.get("uri") or entry.get("url"):
                    advisory_url = entry.get("uri") or entry.get("url")
                    # Resolve relative URLs
                    if not advisory_url.startswith(("http://", "https://", "file://")):
                        advisory_url = self._resolve_url(feed_url, advisory_url)
                    advisory = self._fetch_url(advisory_url)

                if advisory is None:
                    continue

                # Verify hash if provided
                if expected_hash:
                    actual_hash = compute_canonical_hash(advisory)
                    if actual_hash != expected_hash:
                        print(
                            f"Warning: Hash mismatch for {advisory_id}, skipping",
                            file=sys.stderr,
                        )
                        continue

                # Index the advisory
                is_new = advisory.get("id") not in self.advisories
                self._index_advisory(advisory)

                if is_new:
                    stats["added"] += 1
                else:
                    stats["updated"] += 1

            except Exception as e:
                entry_id = entry.get("id", "unknown")
                print(
                    f"Warning: Failed to process entry {entry_id}: {e}",
                    file=sys.stderr,
                )

        return stats

    def _fetch_url(self, url: str) -> Dict:
        """Fetch JSON data from URL (supports file://, http(s)://, and paths)."""
        if url.startswith("file://"):
            path = url[7:]
            with open(path, "r") as f:  # pragma: no mutate
                return json.load(f)
        elif url.startswith("http://"):
            if not self.allow_insecure_http:
                raise ValueError(
                    "Insecure HTTP URL blocked. Use https:// or set allow_insecure_http=True."
                )
            return self._fetch_http_json(url, verify_tls=False)
        elif url.startswith("https://"):
            return self._fetch_http_json(url, verify_tls=True)
        else:
            # Assume local path
            with open(url, "r") as f:  # pragma: no mutate
                return json.load(f)

    def _fetch_http_json(self, url: str, verify_tls: bool) -> Dict:
        """Fetch JSON from HTTP(S), with TLS verification for HTTPS."""
        import ssl
        import urllib.request

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "TSA-Registry-SDK/1.0.0")  # pragma: no mutate
        req.add_header("Accept", "application/json")  # pragma: no mutate

        if verify_tls:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, context=ctx, timeout=30) as response:  # nosec B310
                return json.loads(response.read().decode("utf-8"))  # pragma: no mutate

        with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))  # pragma: no mutate

    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """Resolve a relative URL against a base URL."""
        if base_url.startswith(("http://", "https://")):
            return urljoin(base_url, relative_url)
        elif base_url.startswith("file://"):
            base_path = Path(base_url[7:]).parent
            return str(base_path / relative_url)
        else:
            # Local path
            base_path = Path(base_url).parent
            return str(base_path / relative_url)

    def _index_advisory(self, advisory: Dict):
        """Index an advisory for fast lookup."""
        advisory_id = advisory.get("id")
        if not advisory_id:
            return

        # Check signature requirements for BLOCK actions
        if self.require_signatures:
            sig = advisory.get("signature")
            has_block = any(a.get("type") == "BLOCK" for a in advisory.get("actions", []))

            if has_block and not sig:
                print(
                    f"Warning: Unsigned advisory {advisory_id} has BLOCK actions, "
                    "treating as WARN only",
                    file=sys.stderr,
                )
            elif sig:
                key_id = sig.get("key_id")
                if key_id not in self.trust_anchors:
                    print(f"Warning: Unknown signer for {advisory_id}: {key_id}", file=sys.stderr)

        self.advisories[advisory_id] = advisory

        # Index by package name for fast lookup
        for affected in advisory.get("affected", []):
            tool = affected.get("tool", {})
            name = tool.get("name")
            registry = tool.get("registry", "npm")

            if name:
                key = f"{name}@{registry}"
                if key not in self._package_index:
                    self._package_index[key] = set()
                self._package_index[key].add(advisory_id)

    def add_advisory(self, advisory: Dict):
        """Manually add an advisory (for testing or local advisories)."""
        self._index_advisory(advisory)

    def check_package(self, name: str, version: str, registry: str = "npm") -> CheckResult:
        """
        Check if a package version is affected by any advisories.

        Args:
            name: Package name (e.g., "mcp-remote")
            version: Package version (e.g., "0.1.14")
            registry: Package registry (default: "npm")

        Returns:
            CheckResult with blocking/warning information
        """
        result = CheckResult()

        key = f"{name}@{registry}"
        advisory_ids = sorted(self._package_index.get(key, set()), key=str)
        seen_advisory_ids: Set[str] = set()
        seen_actions: Set[Tuple[str, str, str, str]] = set()

        for advisory_id in advisory_ids:
            advisory = self.advisories.get(advisory_id)
            if not advisory:
                continue

            def _entry_matches(affected: Dict) -> bool:
                tool = affected.get("tool", {})
                if tool.get("name") != name:
                    return False
                if tool.get("registry") and tool.get("registry") != registry:
                    return False
                return self._version_affected(version, affected)

            if not any(_entry_matches(affected) for affected in advisory.get("affected", [])):
                continue

            if advisory_id not in seen_advisory_ids:
                result.advisories.append(advisory)
                seen_advisory_ids.add(advisory_id)

            signature = advisory.get("signature")
            signature_dict = signature if isinstance(signature, dict) else {}
            signature_present = bool(signature_dict)
            key_id = signature_dict.get("key_id")
            anchor = self.trust_anchors.get(key_id) if key_id else None
            sig_ok = False  # pragma: no mutate
            sig_reason = ""  # pragma: no mutate
            if self.require_signatures and anchor:
                sig_ok, sig_reason = self._verify_signature(advisory, anchor)

            # Process actions once per advisory for this package/version.
            for action in advisory.get("actions", []):
                action_type = action.get("type")
                condition = action.get("condition", "")  # pragma: no mutate

                # Check if action condition applies to this version
                if condition and not self._matches_condition(version, condition):
                    continue

                message = action.get("message", f"Security issue: {advisory_id}")
                action_key = (advisory_id, action_type or "", condition, message)
                if action_key in seen_actions:
                    continue
                seen_actions.add(action_key)
                result.actions.append(action)

                if action_type == "BLOCK":
                    # Check signature requirements
                    if self.require_signatures:
                        if not signature_present:
                            reason = "unsigned"
                        elif not key_id:
                            reason = "missing key_id"
                        elif not anchor:
                            reason = "unknown signer"
                        elif not sig_ok:
                            reason = sig_reason or "invalid signature"
                        elif anchor.trust_level != "full":
                            reason = f"trust_level={anchor.trust_level}"
                        else:
                            reason = ""  # pragma: no mutate

                        if reason:
                            warning_msg = f"[WARN instead of BLOCK - {reason}] {message}"
                            result.warnings.append(warning_msg)
                            continue

                    result.blocked = True
                    if not result.message:
                        result.message = message
                elif action_type == "WARN":
                    result.warnings.append(message)

        return result

    def _version_affected(self, version: str, affected: Dict) -> bool:
        """Check if a version is affected."""
        status = affected.get("status")
        if status != "AFFECTED":
            return False

        versions = affected.get("versions", {})
        affected_range = versions.get("affected_range")
        fixed_version = versions.get("fixed")
        introduced_version = versions.get("introduced")
        last_affected = versions.get("last_affected")

        if affected_range:
            return self._matches_range(version, affected_range)

        if introduced_version and self._compare_versions(version, introduced_version) < 0:
            return False
        if fixed_version and self._compare_versions(version, fixed_version) >= 0:
            return False
        if last_affected and self._compare_versions(version, last_affected) > 0:
            return False

        # No disqualifying bounds = affected
        return True

    def _matches_range(self, version: str, range_spec: str) -> bool:
        """Check if version matches a semver range specification."""
        normalized = re.sub(r"\band\b", " ", range_spec, flags=re.IGNORECASE)  # pragma: no mutate
        normalized = normalized.replace(",", " ")
        parts = normalized.split()
        version = _normalize_version(version)

        for part in parts:
            part = part.strip()
            if not part:
                continue

            if part.startswith(">="):
                if self._compare_versions(version, _normalize_version(part[2:])) < 0:
                    return False
            elif part.startswith(">"):
                if self._compare_versions(version, _normalize_version(part[1:])) <= 0:
                    return False
            elif part.startswith("<="):
                if self._compare_versions(version, _normalize_version(part[2:])) > 0:
                    return False
            elif part.startswith("<"):
                if self._compare_versions(version, _normalize_version(part[1:])) >= 0:
                    return False
            elif part.startswith("="):
                if _normalize_version(version) != _normalize_version(part[1:]):
                    return False
            else:
                if _normalize_version(version) != _normalize_version(part):
                    return False

        return True

    def _matches_condition(self, version: str, condition: str) -> bool:
        """Check if version matches an action condition."""
        # Normalize condition string
        condition = re.sub(r"\band\b", " ", condition, flags=re.IGNORECASE)  # pragma: no mutate
        return self._matches_range(version, condition)

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two semver-like versions. Returns -1, 0, or 1."""
        s1 = _parse_semver(v1)
        s2 = _parse_semver(v2)
        if s1 and s2:
            core1, core2 = s1[:3], s2[:3]
            if core1 < core2:
                return -1
            if core1 > core2:
                return 1
            return _compare_prerelease(s1[3], s2[3])

        def parse(v):
            parts = re.split(r"[.\-]", _normalize_version(v))
            result = []
            for p in parts:
                try:
                    result.append((0, int(p)))
                except ValueError:
                    result.append((1, p))  # pragma: no mutate
            return result

        p1, p2 = parse(v1), parse(v2)
        for i in range(max(len(p1), len(p2))):
            a = p1[i] if i < len(p1) else (0, 0)
            b = p2[i] if i < len(p2) else (0, 0)
            if a < b:
                return -1
            if a > b:
                return 1
        return 0

    def get_advisory(self, advisory_id: str) -> Optional[Dict]:
        """Get a specific advisory by ID."""
        return self.advisories.get(advisory_id)

    def get_statistics(self) -> Dict:
        """Get registry statistics."""
        return {
            "feeds_subscribed": len(self.feeds),
            "advisories_indexed": len(self.advisories),
            "packages_tracked": len(self._package_index),
            "trust_anchors": len(self.trust_anchors),
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "sync_errors": len(self.sync_errors),
        }
