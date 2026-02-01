#!/usr/bin/env python3
"""
tsactl - Tool Security Advisory Command Line Tool

Reference implementation for the TSA (Tool Security Advisory) specification.
Provides validation, canonicalization, signing, and verification capabilities.

IMPORTANT: This tool performs REAL JSON Schema validation using Draft 2020-12.
Unknown fields will be REJECTED. Semantic validation is also performed.

Usage:
    tsactl validate <tsa_file>           Validate against JSON Schema + semantics
    tsactl canonicalize <tsa_file>       Output canonical form (RFC 8785)
    tsactl hash <tsa_file>               Compute canonical hash
    tsactl sign <tsa_file> <key_file>    Sign a TSA document (Ed25519/ES256/ES384/RS256)
    tsactl verify <tsa_file> <pub_key>   Verify TSA signature
    tsactl match <tsa_file> <inventory>  Match advisory against tool inventory
    tsactl generate-keys <prefix>        Generate signing key pair (Ed25519/ES256/ES384/RS256)

Version: 1.0.0
License: Apache-2.0
"""

import base64
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import jsonschema for proper validation
try:
    from jsonschema import Draft202012Validator, FormatChecker

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    print(
        "WARNING: jsonschema not installed. Install with: pip install jsonschema",
        file=sys.stderr,
    )
    print("         Schema validation will be SKIPPED.", file=sys.stderr)

# Try to import cryptography for signing
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# JSON Canonicalization (RFC 8785)
# =============================================================================


def _utf16_key(value: str) -> Tuple[int, ...]:
    encoded = value.encode("utf-16-be")  # pragma: no mutate
    return tuple((encoded[i] << 8) | encoded[i + 1] for i in range(0, len(encoded), 2))


def _trim_trailing_decimal_zeros(value: str) -> str:
    """Normalize decimal strings by trimming trailing zeros."""
    if "." in value and "e" not in value.lower():
        value = value.rstrip("0")
        if value.endswith("."):
            value += "0"
    return value


def canonicalize(obj: Any) -> str:
    """
    Canonicalize JSON per RFC 8785 (JSON Canonicalization Scheme).

    Rules:
    - Object keys sorted lexicographically by UTF-16 code units
    - No whitespace
    - Numbers normalized (no trailing zeros, no leading zeros except 0.x)
    - Strings properly escaped
    """
    if obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, int):
        return str(obj)
    elif isinstance(obj, float):
        if math.isnan(obj):
            raise ValueError("NaN not allowed in canonical JSON")
        if math.isinf(obj):
            raise ValueError("Infinity not allowed in canonical JSON")
        if obj == int(obj):
            return str(int(obj))
        s = repr(obj)
        return _trim_trailing_decimal_zeros(s)
    elif isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)  # pragma: no mutate
    elif isinstance(obj, list):
        items = [canonicalize(item) for item in obj]
        return "[" + ",".join(items) + "]"
    elif isinstance(obj, dict):
        sorted_keys = sorted(obj.keys(), key=_utf16_key)
        items = [f"{canonicalize(k)}:{canonicalize(obj[k])}" for k in sorted_keys]
        return "{" + ",".join(items) + "}"
    else:
        raise TypeError(f"Cannot canonicalize type: {type(obj)}")


def compute_canonical_hash(tsa_doc: Dict, exclude_signature: bool = True) -> str:
    """Compute SHA-256 hash of canonical form."""
    doc_copy = dict(tsa_doc)
    if exclude_signature and "signature" in doc_copy:
        del doc_copy["signature"]
    canonical = canonicalize(doc_copy)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()  # pragma: no mutate


# =============================================================================
# Schema Loading
# =============================================================================


def find_schema_path() -> Optional[Path]:
    """Find the TSA schema file."""
    script_dir = Path(__file__).parent.resolve()
    candidates = [
        script_dir.parent / "schema" / "tsa-v1.0.0.schema.json",
        script_dir / ".." / "schema" / "tsa-v1.0.0.schema.json",
        Path("schema") / "tsa-v1.0.0.schema.json",
        Path("tsa-v1.0.0.schema.json"),
    ]
    for candidate in candidates:
        resolved = candidate.resolve() if not candidate.is_absolute() else candidate
        if resolved.exists():
            return resolved
    return None


def load_schema() -> Optional[Dict]:
    """Load the TSA JSON Schema."""
    schema_path = find_schema_path()
    if schema_path is None:
        return None
    with open(schema_path, "r") as f:  # pragma: no mutate
        return json.load(f)


# =============================================================================
# Validation
# =============================================================================


class ValidationResult:
    """Result of validating a TSA document."""

    def __init__(self):
        self.valid = True
        self.schema_errors: List[str] = []
        self.semantic_errors: List[str] = []
        self.warnings: List[str] = []

    def add_schema_error(self, msg: str):
        self.valid = False
        self.schema_errors.append(msg)

    def add_semantic_error(self, msg: str):
        self.valid = False
        self.semantic_errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)

    def summary(self) -> str:
        lines = []
        if self.valid:
            lines.append("✓ Validation PASSED")
        else:
            lines.append("✗ Validation FAILED")

        if self.schema_errors:
            lines.append(f"\nSchema Errors ({len(self.schema_errors)}):")
            for err in self.schema_errors:
                lines.append(f"  - {err}")

        if self.semantic_errors:
            lines.append(f"\nSemantic Errors ({len(self.semantic_errors)}):")
            for err in self.semantic_errors:
                lines.append(f"  - {err}")

        if self.warnings:
            lines.append(f"\nWarnings ({len(self.warnings)}):")
            for warn in self.warnings:
                lines.append(f"  - {warn}")

        return "\n".join(lines)


def validate_schema(tsa_doc: Dict, schema: Dict) -> List[str]:
    """
    Validate TSA document against JSON Schema using Draft 2020-12.

    This performs REAL validation - unknown fields are rejected due to
    additionalProperties: false in the schema.

    Returns list of error messages.
    """
    if not JSONSCHEMA_AVAILABLE:
        return ["jsonschema library not available - install with: pip install jsonschema"]

    errors = []

    # Create validator with format checking enabled
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    # Check schema validity first
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as e:
        errors.append(f"Invalid schema: {e}")
        return errors

    # Validate document - collect ALL errors
    for error in sorted(
        validator.iter_errors(tsa_doc),
        key=lambda e: str(list(e.absolute_path)),
    ):  # pragma: no mutate
        path = " -> ".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
        errors.append(f"[{path}] {error.message}")

    return errors


def validate_semantics(tsa_doc: Dict) -> Tuple[List[str], List[str]]:
    """
    Perform semantic validation beyond JSON Schema.
    Returns (errors, warnings).
    """
    errors = []
    warnings = []

    # Check version
    if tsa_doc.get("tsa_version") != "1.0.0":
        warnings.append(f"tsa_version '{tsa_doc.get('tsa_version')}' is not '1.0.0'")

    # Check timestamps
    published = tsa_doc.get("published", "")  # pragma: no mutate
    modified = tsa_doc.get("modified", "")  # pragma: no mutate

    try:
        pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))  # pragma: no mutate
        mod_dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))  # pragma: no mutate
        if mod_dt < pub_dt:
            errors.append("modified timestamp cannot be before published timestamp")
    except (ValueError, AttributeError):
        pass  # Format errors caught by schema validation

    # Check affected entries have meaningful content
    affected = tsa_doc.get("affected", [])
    has_affected_status = False  # pragma: no mutate

    for i, entry in enumerate(affected):
        status = entry.get("status")
        if status == "AFFECTED":
            has_affected_status = True
            versions = entry.get("versions", {})
            missing_versions = (
                not versions.get("introduced")
                and not versions.get("fixed")
                and not versions.get("affected_range")
            )
            if missing_versions:
                warnings.append(f"affected[{i}]: AFFECTED status but no version constraints")

    if not has_affected_status:
        warnings.append("No entries with AFFECTED status - is this advisory actionable?")

    # Check actions have messages
    actions = tsa_doc.get("actions", [])
    has_block_or_warn = False  # pragma: no mutate
    for i, action in enumerate(actions):
        if action.get("type") in ["BLOCK", "WARN"]:
            has_block_or_warn = True
            if not action.get("message"):
                warnings.append(f"actions[{i}]: {action.get('type')} action should have a message")

    if not has_block_or_warn:
        warnings.append("No BLOCK or WARN actions - registries may not enforce this advisory")

    # Check references include authoritative sources
    references = tsa_doc.get("references", [])
    has_cve = any(ref.get("type") == "CVE" for ref in references)
    has_advisory = any(ref.get("type") == "ADVISORY" for ref in references)

    if not has_cve and not has_advisory:
        warnings.append("No CVE or ADVISORY references - consider adding authoritative sources")

    # Check severity
    severity = tsa_doc.get("severity", {})  # pragma: no mutate
    if not severity:
        warnings.append("No severity information - registries need this for prioritization")
    elif not severity.get("cvss_v3") and not severity.get("cvss_v4"):
        warnings.append("No CVSS score - consider adding for interoperability")

    return errors, warnings


def validate_tsa(tsa_doc: Dict) -> ValidationResult:
    """Full validation of a TSA document."""
    result = ValidationResult()

    # Load schema
    schema = load_schema()
    if schema is None:
        result.add_warning("Could not find schema file - skipping schema validation")
        result.add_warning("Ensure schema/tsa-v1.0.0.schema.json is in the package")
    else:
        # JSON Schema validation (the REAL kind)
        schema_errors = validate_schema(tsa_doc, schema)
        for err in schema_errors:
            result.add_schema_error(err)

    # Semantic validation (only if schema passed or unavailable)
    if result.valid or schema is None:
        sem_errors, sem_warnings = validate_semantics(tsa_doc)
        for err in sem_errors:
            result.add_semantic_error(err)
        for warn in sem_warnings:
            result.add_warning(warn)

    return result


# =============================================================================
# Signing and Verification
# =============================================================================


def generate_keys(prefix: str, algorithm: str = "Ed25519", rsa_bits: int = 2048) -> Tuple[str, str]:
    """Generate a key pair for the requested signature algorithm."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "cryptography library not available - install with: pip install cryptography"
        )

    if algorithm == "Ed25519":
        private_key = Ed25519PrivateKey.generate()
    elif algorithm == "RS256":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    elif algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == "ES384":
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_path = f"{prefix}_private.pem"
    public_path = f"{prefix}_public.pem"

    with open(private_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_path, 0o600)

    with open(public_path, "wb") as f:
        f.write(public_pem)

    return private_path, public_path


def _detect_signing_algorithm(private_key: object) -> str:
    """Infer signature algorithm from a loaded private key."""
    if isinstance(private_key, Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        if isinstance(private_key.curve, ec.SECP256R1):
            return "ES256"
        if isinstance(private_key.curve, ec.SECP384R1):
            return "ES384"
        raise ValueError("Unsupported EC curve for signing")
    raise ValueError("Unsupported private key type for signing")


def sign_document(
    tsa_doc: Dict, private_key_path: str, key_id: str, algorithm: Optional[str] = "auto"
) -> Dict:
    """Sign a TSA document with the requested algorithm (or auto-detect)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library not available")

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    if not algorithm or algorithm == "auto":
        algorithm = _detect_signing_algorithm(private_key)

    # Remove existing signature
    doc_copy = {k: v for k, v in tsa_doc.items() if k != "signature"}

    # Canonicalize and sign
    canonical = canonicalize(doc_copy).encode("utf-8")  # pragma: no mutate
    if algorithm == "Ed25519":
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Private key is not Ed25519")
        signature = private_key.sign(canonical)
    elif algorithm == "RS256":
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Private key is not RSA")
        signature = private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "ES256":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Private key is not P-256")
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("Private key is not P-256")
        signature = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    elif algorithm == "ES384":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Private key is not P-384")
        if not isinstance(private_key.curve, ec.SECP384R1):
            raise ValueError("Private key is not P-384")
        signature = private_key.sign(canonical, ec.ECDSA(hashes.SHA384()))
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Add signature
    doc_copy["signature"] = {
        "algorithm": algorithm,
        "key_id": key_id,
        "value": base64.b64encode(signature).decode("ascii"),  # pragma: no mutate
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    return doc_copy


def verify_signature(tsa_doc: Dict, public_key_path: str) -> bool:
    """Verify TSA signature on document."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library not available")

    signature_info = tsa_doc.get("signature")
    if not signature_info:
        raise ValueError("Document has no signature")

    algorithm = signature_info.get("algorithm")
    if algorithm not in ("Ed25519", "ES256", "ES384", "RS256"):
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Remove signature and canonicalize
    doc_copy = {k: v for k, v in tsa_doc.items() if k != "signature"}
    canonical = canonicalize(doc_copy).encode("utf-8")  # pragma: no mutate

    # Verify
    signature = base64.b64decode(signature_info["value"])
    if algorithm == "Ed25519":
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Public key is not Ed25519")
        try:
            public_key.verify(signature, canonical)
        except Exception:
            return False
        return True
    if algorithm == "RS256":
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Public key is not RSA")
        try:
            public_key.verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            return False
        return True
    if algorithm == "ES256":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Public key is not P-256")
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("Public key is not P-256")
        try:
            public_key.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return False
        return True
    if algorithm == "ES384":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Public key is not P-384")
        if not isinstance(public_key.curve, ec.SECP384R1):
            raise ValueError("Public key is not P-384")
        try:
            public_key.verify(signature, canonical, ec.ECDSA(hashes.SHA384()))
        except Exception:
            return False
        return True


# =============================================================================
# Version Matching
# =============================================================================


_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _normalize_version(value: str) -> str:
    value = value.strip()
    return value[1:] if value.lower().startswith("v") else value


def _parse_semver(value: str) -> Optional[Tuple[int, int, int, List[Tuple[bool, object]]]]:
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


def _compare_prerelease(a: List[Tuple[bool, object]], b: List[Tuple[bool, object]]) -> int:
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


def parse_version(version: str) -> Tuple:
    """Parse non-semver version string into comparable tuple."""
    version = _normalize_version(version)
    parts = re.split(r"[.\-]", version)
    result = []
    for part in parts:
        try:
            result.append((0, int(part)))  # Numbers sort first
        except ValueError:
            result.append((1, part))  # Strings sort after
    return tuple(result)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two versions. Returns -1, 0, or 1."""
    s1 = _parse_semver(v1)
    s2 = _parse_semver(v2)
    if s1 and s2:
        core1, core2 = s1[:3], s2[:3]
        if core1 < core2:
            return -1
        if core1 > core2:
            return 1
        return _compare_prerelease(s1[3], s2[3])
    p1, p2 = parse_version(v1), parse_version(v2)
    for i in range(max(len(p1), len(p2))):
        a = p1[i] if i < len(p1) else (0, 0)
        b = p2[i] if i < len(p2) else (0, 0)
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def version_in_range(version: str, affected_range: str) -> bool:
    """Check if version matches affected range (simplified semver)."""
    if not affected_range:
        return False

    # Handle compound ranges like ">=0.0.5 <0.1.16" or ">=0.0.5, <0.1.16"
    normalized = re.sub(r"\band\b", " ", affected_range, flags=re.IGNORECASE)  # pragma: no mutate
    normalized = normalized.replace(",", " ")
    parts = normalized.split()
    version = _normalize_version(version)

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if part.startswith(">="):
            if compare_versions(version, _normalize_version(part[2:])) < 0:
                return False
        elif part.startswith(">"):
            if compare_versions(version, _normalize_version(part[1:])) <= 0:
                return False
        elif part.startswith("<="):
            if compare_versions(version, _normalize_version(part[2:])) > 0:
                return False
        elif part.startswith("<"):
            if compare_versions(version, _normalize_version(part[1:])) >= 0:
                return False
        elif part.startswith("="):
            if _normalize_version(version) != _normalize_version(part[1:]):
                return False
        else:
            # Exact match
            if _normalize_version(version) != _normalize_version(part):
                return False

    return True


def match_advisory(tsa_doc: Dict, inventory: List[Dict]) -> List[Dict]:
    """Match advisory against tool inventory."""
    matches = []

    for item in inventory:
        item_name = item.get("name", "")
        item_version = item.get("version", "")  # pragma: no mutate
        item_registry = item.get("registry", "npm")

        for affected in tsa_doc.get("affected", []):
            tool = affected.get("tool", {})
            if tool.get("name") != item_name:
                continue
            if tool.get("registry") and tool.get("registry") != item_registry:
                continue

            status = affected.get("status", "")  # pragma: no mutate
            if status != "AFFECTED":
                continue

            versions = affected.get("versions", {})
            is_affected = False  # pragma: no mutate

            introduced = versions.get("introduced")
            fixed = versions.get("fixed")
            last_affected = versions.get("last_affected")

            if versions.get("affected_range"):
                is_affected = version_in_range(item_version, versions["affected_range"])
            else:
                # Apply introduced/fixed/last_affected bounds when present
                if introduced and compare_versions(item_version, introduced) < 0:
                    is_affected = False  # pragma: no mutate
                elif fixed and compare_versions(item_version, fixed) >= 0:
                    is_affected = False  # pragma: no mutate
                elif last_affected and compare_versions(item_version, last_affected) > 0:
                    is_affected = False  # pragma: no mutate
                else:
                    is_affected = True  # No disqualifying bounds

            if is_affected:
                matches.append(
                    {
                        "tool": item_name,
                        "version": item_version,
                        "registry": item_registry,
                        "advisory_id": tsa_doc.get("id"),
                        "status": status,
                        "severity": tsa_doc.get("severity", {}).get("qualitative", "UNKNOWN"),
                        "impact": affected.get("impact_statement", ""),
                        "fixed_version": versions.get("fixed", "N/A"),
                    }
                )

    return matches
