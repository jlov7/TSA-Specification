#!/usr/bin/env python3
"""
run_tests.py - TSA Specification Test Harness

Comprehensive end-to-end tests for the TSA specification.
Validates schemas, advisories, tools, and SDK functionality.

Usage:
    python3 tests/run_tests.py
    python3 tests/run_tests.py -v  # Verbose output

Exit codes:
    0 - All tests passed
    1 - One or more tests failed
"""

import argparse
import base64
import builtins
import contextlib
import importlib.util
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


# Add tools to path
def find_repo_root(start: Path) -> Path:
    current = start
    for _ in range(6):
        if (current / "schema").exists() and (current / "tests").exists():
            return current
        current = current.parent
    return start


THIS_ROOT = Path(__file__).resolve().parent.parent
if THIS_ROOT.name == "mutants":
    MUTANTS_ROOT = THIS_ROOT
    REPO_ROOT = THIS_ROOT.parent
else:
    MUTANTS_ROOT = None
    REPO_ROOT = find_repo_root(Path(__file__).resolve().parent)

if MUTANTS_ROOT and (MUTANTS_ROOT / "tools").exists():
    sys.path.insert(0, str(MUTANTS_ROOT))
    sys.path.insert(1, str(REPO_ROOT))
else:
    sys.path.insert(0, str(REPO_ROOT))

TOOLS_ROOT = MUTANTS_ROOT if MUTANTS_ROOT and (MUTANTS_ROOT / "tools").exists() else REPO_ROOT

if MUTANTS_ROOT and (MUTANTS_ROOT / "tools").exists():
    import types

    tools_pkg = types.ModuleType("tools")
    tools_pkg.__path__ = [
        str(MUTANTS_ROOT / "tools"),
        str(REPO_ROOT / "tools"),
    ]
    sys.modules["tools"] = tools_pkg


def resolve_tool_script(name: str) -> Path:
    primary = TOOLS_ROOT / "tools" / name
    if primary.exists():
        return primary
    return REPO_ROOT / "tools" / name


# Test state
PASSED = 0
FAILED = 0
VERBOSE = False


def log(msg: str, indent: int = 0):
    """Print log message."""
    prefix = "  " * indent
    print(f"{prefix}{msg}")


def load_module_from_path(name: str, path: Path, blocked_imports: list = None):
    """Load a module from path, optionally blocking selected imports."""
    blocked = set(blocked_imports or [])
    original_import = builtins.__import__

    def guarded_import(import_name, globals=None, locals=None, fromlist=(), level=0):
        for blocked_name in blocked:
            if import_name == blocked_name or import_name.startswith(blocked_name + "."):
                raise ImportError(f"Blocked import: {import_name}")
        return original_import(import_name, globals, locals, fromlist, level)

    try:
        builtins.__import__ = guarded_import
        spec = importlib.util.spec_from_file_location(name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec for {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        builtins.__import__ = original_import


def test_pass(name: str):
    """Record a passing test."""
    global PASSED
    PASSED += 1
    log(f"✓ {name}")


def test_fail(name: str, reason: str):
    """Record a failing test."""
    global FAILED
    FAILED += 1
    log(f"✗ {name}")
    log(f"  Reason: {reason}", indent=1)


# =============================================================================
# Schema Tests
# =============================================================================


def test_schema_validity():
    """Test that all schemas are valid JSON Schema documents."""
    log("\n=== Schema Validity Tests ===")

    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        test_fail("Schema validity", "jsonschema not installed")
        return

    schema_dir = REPO_ROOT / "schema"

    for schema_file in schema_dir.glob("*.schema.json"):
        try:
            with open(schema_file) as f:
                schema = json.load(f)

            # Check schema is valid
            Draft202012Validator.check_schema(schema)
            test_pass(f"Schema valid: {schema_file.name}")

            # Check required fields
            if "$schema" not in schema:
                test_fail(f"Schema $schema: {schema_file.name}", "Missing $schema")
            elif "2020-12" in schema["$schema"]:
                test_pass(f"Schema uses Draft 2020-12: {schema_file.name}")
            else:
                schema_value = schema.get("$schema")
                test_fail(
                    f"Schema draft: {schema_file.name}",
                    f"Expected 2020-12, got {schema_value}",
                )

            if "$id" not in schema:
                test_fail(f"Schema $id: {schema_file.name}", "Missing $id")
            else:
                test_pass(f"Schema has $id: {schema_file.name}")

        except json.JSONDecodeError as e:
            test_fail(f"Schema JSON: {schema_file.name}", str(e))
        except Exception as e:
            test_fail(f"Schema validation: {schema_file.name}", str(e))


def test_schema_strictness():
    """Test that schemas use additionalProperties: false."""
    log("\n=== Schema Strictness Tests ===")

    schema_dir = REPO_ROOT / "schema"

    for schema_file in schema_dir.glob("*.schema.json"):
        try:
            with open(schema_file) as f:
                schema = json.load(f)

            # Check root has additionalProperties: false
            if schema.get("additionalProperties") is False:
                test_pass(f"Root strict: {schema_file.name}")
            else:
                test_fail(f"Root strict: {schema_file.name}", "additionalProperties not false")

            # Check $defs have additionalProperties: false
            defs = schema.get("$defs", {})
            for def_name, def_schema in defs.items():
                if def_schema.get("type") == "object":
                    if def_schema.get("additionalProperties") is False:
                        if VERBOSE:
                            test_pass(f"  Def strict: {def_name}")
                    else:
                        test_fail(
                            f"Def strict: {schema_file.name}/${def_name}",
                            "additionalProperties not false",
                        )

        except Exception as e:
            test_fail(f"Schema strictness: {schema_file.name}", str(e))


# =============================================================================
# Advisory Tests
# =============================================================================


def test_advisory_validation():
    """Test that all advisories validate against the schema."""
    log("\n=== Advisory Validation Tests ===")

    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        test_fail("Advisory validation", "jsonschema not installed")
        return

    # Load schema
    schema_path = REPO_ROOT / "schema" / "tsa-v1.0.0.schema.json"
    try:
        with open(schema_path) as f:
            schema = json.load(f)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except Exception as e:
        test_fail("Load TSA schema", str(e))
        return

    # Validate each advisory
    advisory_dir = REPO_ROOT / "advisories"
    for advisory_file in sorted(advisory_dir.glob("*.tsa.json")):
        try:
            with open(advisory_file) as f:
                advisory = json.load(f)

            errors = list(validator.iter_errors(advisory))
            if errors:
                test_fail(
                    f"Advisory: {advisory_file.name}",
                    f"{len(errors)} error(s): {errors[0].message}",
                )
            else:
                test_pass(f"Advisory valid: {advisory_file.name}")

        except json.JSONDecodeError as e:
            test_fail(f"Advisory JSON: {advisory_file.name}", str(e))
        except Exception as e:
            test_fail(f"Advisory: {advisory_file.name}", str(e))


def test_advisory_cve_format():
    """Test that CVE references use correct format."""
    log("\n=== Advisory CVE Format Tests ===")

    import re

    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")

    advisory_dir = REPO_ROOT / "advisories"
    for advisory_file in sorted(advisory_dir.glob("*.tsa.json")):
        try:
            with open(advisory_file) as f:
                advisory = json.load(f)

            refs = advisory.get("references", [])
            cve_refs = [r for r in refs if r.get("type") == "CVE"]

            for ref in cve_refs:
                cve_id = ref.get("id", "")
                if cve_pattern.match(cve_id):
                    test_pass(f"CVE format: {advisory_file.name} - {cve_id}")
                else:
                    test_fail(f"CVE format: {advisory_file.name}", f"Invalid CVE ID: {cve_id}")

        except Exception as e:
            test_fail(f"CVE check: {advisory_file.name}", str(e))


# =============================================================================
# Feed Tests
# =============================================================================


def test_feed_validation():
    """Test that feed files validate against the feed schema."""
    log("\n=== Feed Validation Tests ===")

    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        test_fail("Feed validation", "jsonschema not installed")
        return

    # Load feed schema
    schema_path = REPO_ROOT / "schema" / "tsa-feed-v1.0.0.schema.json"
    if not schema_path.exists():
        test_fail("Feed schema", "tsa-feed-v1.0.0.schema.json not found")
        return

    try:
        with open(schema_path) as f:
            schema = json.load(f)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except Exception as e:
        test_fail("Load feed schema", str(e))
        return

    # Validate each feed
    feed_dir = REPO_ROOT / "feeds"
    for feed_file in sorted(feed_dir.glob("*.json")):
        try:
            with open(feed_file) as f:
                feed = json.load(f)

            errors = list(validator.iter_errors(feed))
            if errors:
                test_fail(f"Feed: {feed_file.name}", f"{len(errors)} error(s): {errors[0].message}")
            else:
                test_pass(f"Feed valid: {feed_file.name}")

        except Exception as e:
            test_fail(f"Feed: {feed_file.name}", str(e))


def test_feed_hash_integrity():
    """Test that feed canonical hashes match advisory hashes."""
    log("\n=== Feed Hash Integrity Tests ===")

    try:
        from tools.tsactl_core import compute_canonical_hash
    except ImportError:
        test_fail("Hash integrity", "Could not import tsactl")
        return

    feed_dir = REPO_ROOT / "feeds"
    advisory_dir = REPO_ROOT / "advisories"

    for feed_file in sorted(feed_dir.glob("*.json")):
        try:
            with open(feed_file) as f:
                feed = json.load(f)

            for entry in feed.get("advisories", []):
                advisory_id = entry.get("id")
                expected_hash = entry.get("canonical_hash")

                # Find matching advisory file
                advisory_files = list(advisory_dir.glob(f"*{advisory_id}*.json"))
                if not advisory_files:
                    if VERBOSE:
                        log(f"  Skip hash check: {advisory_id} (no local file)")
                    continue

                with open(advisory_files[0]) as f:
                    advisory = json.load(f)

                actual_hash = compute_canonical_hash(advisory)

                if expected_hash == actual_hash:
                    test_pass(f"Hash match: {advisory_id}")
                else:
                    test_fail(
                        f"Hash match: {advisory_id}",
                        f"Expected {expected_hash[:20]}..., got {actual_hash[:20]}...",
                    )

        except Exception as e:
            test_fail(f"Hash integrity: {feed_file.name}", str(e))


# =============================================================================
# Tool Tests
# =============================================================================


def test_tsactl_validate():
    """Test tsactl validate command."""
    log("\n=== tsactl Validate Tests ===")

    try:
        from tools.tsactl_core import load_schema, validate_tsa
    except ImportError:
        test_fail("tsactl import", "Could not import tsactl")
        return

    # Check schema loads
    schema = load_schema()
    if schema:
        test_pass("tsactl loads schema")
    else:
        test_fail("tsactl loads schema", "Schema not found")
        return

    # Test validation on minimal test vector
    test_vector = REPO_ROOT / "test-vectors" / "tv01-minimal.tsa.json"
    if test_vector.exists():
        try:
            with open(test_vector) as f:
                doc = json.load(f)
            result = validate_tsa(doc)
            if result.valid:
                test_pass("tsactl validates minimal test vector")
            else:
                test_fail("tsactl validates minimal", result.summary())
        except Exception as e:
            test_fail("tsactl minimal test", str(e))
    else:
        test_fail("tsactl minimal test", "Test vector not found")


def test_tsactl_canonicalize():
    """Test tsactl canonicalization."""
    log("\n=== tsactl Canonicalization Tests ===")

    try:
        from tools.tsactl_core import canonicalize, _trim_trailing_decimal_zeros, _utf16_key
    except ImportError:
        test_fail("Canonicalize import", "Could not import tsactl")
        return

    # Test determinism
    doc1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    doc2 = {"a": 1, "c": [3, 2, 1], "b": 2}

    c1 = canonicalize(doc1)
    c2 = canonicalize(doc2)

    if c1 == c2:
        test_pass("Canonicalization is deterministic")
    else:
        test_fail("Canonicalization determinism", f"{c1} != {c2}")

    # Test no whitespace
    if " " not in c1 and "\n" not in c1:
        test_pass("Canonical form has no whitespace")
    else:
        test_fail("Canonical whitespace", "Found whitespace in canonical form")

    # Test sorted keys
    expected = '{"a":1,"b":2,"c":[3,2,1]}'
    if c1 == expected:
        test_pass("Canonical keys are sorted")
    else:
        test_fail("Canonical key order", f"Expected {expected}, got {c1}")

    # Test UTF-16 key ordering for non-ASCII keys
    private_use = "\ue000"
    emoji = "😀"
    doc_unicode = {private_use: 1, emoji: 2}
    c_unicode = canonicalize(doc_unicode)
    expected_unicode = f'{{"{emoji}":2,"{private_use}":1}}'
    if c_unicode == expected_unicode:
        test_pass("Canonical UTF-16 key ordering")
    else:
        test_fail("Canonical UTF-16 key order", f"Expected {expected_unicode}, got {c_unicode}")

    if _utf16_key(emoji) == (0xD83D, 0xDE00):
        test_pass("UTF-16 key tuple")
    else:
        test_fail("UTF-16 key tuple", f"Unexpected tuple {_utf16_key(emoji)}")

    if _utf16_key(emoji) < _utf16_key(private_use):
        test_pass("UTF-16 key ordering numeric")
    else:
        test_fail("UTF-16 key ordering numeric", "Expected emoji before private-use char")

    # Float normalization helper
    if _trim_trailing_decimal_zeros("1.2300") == "1.23":
        test_pass("Trim trailing zeros")
    else:
        test_fail("Trim trailing zeros", "Expected 1.23")

    if _trim_trailing_decimal_zeros("0.1200") == "0.12":
        test_pass("Trim preserves leading zero")
    else:
        test_fail("Trim preserves leading zero", "Expected 0.12")

    if _trim_trailing_decimal_zeros("1.0") == "1.0":
        test_pass("Trim trailing dot")
    else:
        test_fail("Trim trailing dot", "Expected 1.0")

    if _trim_trailing_decimal_zeros("1.25e-10") == "1.25e-10":
        test_pass("Trim ignores exponent")
    else:
        test_fail("Trim ignores exponent", "Expected exponent unchanged")

    if _trim_trailing_decimal_zeros("1.2300X") == "1.2300X":
        test_pass("Trim ignores non-numeric suffix")
    else:
        test_fail("Trim ignores non-numeric suffix", "Unexpected trimming of suffix")

    c_float = canonicalize({"f": 0.125})
    if c_float == '{"f":0.125}':
        test_pass("Canonical float leading zero")
    else:
        test_fail("Canonical float leading zero", f'Expected {{"f":0.125}}, got {c_float}')


def test_tsactl_signing():
    """Test tsactl signing and verification."""
    log("\n=== tsactl Signing Tests ===")

    try:
        from tools.tsactl_core import canonicalize, generate_keys, sign_document, verify_signature
    except ImportError:
        test_fail("Signing import", "Could not import cryptography")
        return

    # Generate temp keys
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            priv_path, pub_path = generate_keys(os.path.join(tmpdir, "test"))
            test_pass("Key generation")
            if os.name != "nt":
                mode = os.stat(priv_path).st_mode & 0o777
                if mode == 0o600:
                    test_pass("Key permissions 600")
                else:
                    test_fail("Key permissions 600", f"Expected 0o600, got {oct(mode)}")
        except Exception as e:
            test_fail("Key generation", str(e))
            return

        # Sign a document
        doc = {"tsa_version": "1.0.0", "id": "TSA-TEST-0001", "title": "Test advisory for signing"}

        try:
            signed = sign_document(doc, priv_path, "test:key1")
            if "signature" in signed:
                test_pass("Document signing")
            else:
                test_fail("Document signing", "No signature in result")
                return
        except Exception as e:
            test_fail("Document signing", str(e))
            return

        # Verify signature
        try:
            if verify_signature(signed, pub_path):
                test_pass("Signature verification")
            else:
                test_fail("Signature verification", "Verification returned False")
        except Exception as e:
            test_fail("Signature verification", str(e))

        # Verify RSA/ECDSA signatures
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        except ImportError as e:
            test_fail("Signature algorithm imports", str(e))
        else:
            base_doc = {
                "tsa_version": "1.0.0",
                "id": "TSA-TEST-0001",
                "title": "Test advisory for signing",
            }
            canonical = canonicalize(base_doc).encode("utf-8")

            rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_public = rsa_private.public_key()
            rsa_sig = rsa_private.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
            rsa_doc = dict(base_doc)
            rsa_doc["signature"] = {
                "algorithm": "RS256",
                "key_id": "test:rsa",
                "value": base64.b64encode(rsa_sig).decode("ascii"),
            }
            rsa_pub_path = os.path.join(tmpdir, "rsa_pub.pem")
            with open(rsa_pub_path, "wb") as handle:
                handle.write(
                    rsa_public.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            if verify_signature(rsa_doc, rsa_pub_path):
                test_pass("Signature verification RS256")
            else:
                test_fail("Signature verification RS256", "Verification returned False")

            ec256_private = ec.generate_private_key(ec.SECP256R1())
            ec256_public = ec256_private.public_key()
            ec256_sig = ec256_private.sign(canonical, ec.ECDSA(hashes.SHA256()))
            ec256_doc = dict(base_doc)
            ec256_doc["signature"] = {
                "algorithm": "ES256",
                "key_id": "test:ec256",
                "value": base64.b64encode(ec256_sig).decode("ascii"),
            }
            ec256_pub_path = os.path.join(tmpdir, "ec256_pub.pem")
            with open(ec256_pub_path, "wb") as handle:
                handle.write(
                    ec256_public.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            if verify_signature(ec256_doc, ec256_pub_path):
                test_pass("Signature verification ES256")
            else:
                test_fail("Signature verification ES256", "Verification returned False")

            ec384_private = ec.generate_private_key(ec.SECP384R1())
            ec384_public = ec384_private.public_key()
            ec384_sig = ec384_private.sign(canonical, ec.ECDSA(hashes.SHA384()))
            ec384_doc = dict(base_doc)
            ec384_doc["signature"] = {
                "algorithm": "ES384",
                "key_id": "test:ec384",
                "value": base64.b64encode(ec384_sig).decode("ascii"),
            }
            ec384_pub_path = os.path.join(tmpdir, "ec384_pub.pem")
            with open(ec384_pub_path, "wb") as handle:
                handle.write(
                    ec384_public.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            if verify_signature(ec384_doc, ec384_pub_path):
                test_pass("Signature verification ES384")
            else:
                test_fail("Signature verification ES384", "Verification returned False")

        # Sign/verify with alternate algorithms via tsactl_core
        try:
            from cryptography.hazmat.primitives import serialization

            rsa_priv, rsa_pub = generate_keys(os.path.join(tmpdir, "rsa"), algorithm="RS256")
            rsa_signed = sign_document(doc, rsa_priv, "test:rsa", algorithm="RS256")
            if verify_signature(rsa_signed, rsa_pub):
                test_pass("tsactl sign RS256")
            else:
                test_fail("tsactl sign RS256", "Verification returned False")

            rsa_signed_auto = sign_document(doc, rsa_priv, "test:rsa")
            rsa_auto_alg = rsa_signed_auto.get("signature", {}).get("algorithm")
            if rsa_auto_alg == "RS256" and verify_signature(rsa_signed_auto, rsa_pub):
                test_pass("tsactl sign RS256 auto")
            else:
                test_fail("tsactl sign RS256 auto", "Auto detection failed")

            with open(rsa_priv, "rb") as handle:
                rsa_key = serialization.load_pem_private_key(handle.read(), password=None)
            if getattr(rsa_key, "key_size", None) == 2048:
                test_pass("tsactl rsa key size default")
            else:
                test_fail("tsactl rsa key size default", f"key_size={rsa_key.key_size}")

            ec256_priv, ec256_pub = generate_keys(os.path.join(tmpdir, "ec256"), algorithm="ES256")
            ec256_signed = sign_document(doc, ec256_priv, "test:ec256", algorithm="ES256")
            if verify_signature(ec256_signed, ec256_pub):
                test_pass("tsactl sign ES256")
            else:
                test_fail("tsactl sign ES256", "Verification returned False")

            ec256_signed_auto = sign_document(doc, ec256_priv, "test:ec256")
            ec256_auto_alg = ec256_signed_auto.get("signature", {}).get("algorithm")
            if ec256_auto_alg == "ES256" and verify_signature(ec256_signed_auto, ec256_pub):
                test_pass("tsactl sign ES256 auto")
            else:
                test_fail("tsactl sign ES256 auto", "Auto detection failed")

            ec384_priv, ec384_pub = generate_keys(os.path.join(tmpdir, "ec384"), algorithm="ES384")
            ec384_signed = sign_document(doc, ec384_priv, "test:ec384", algorithm="ES384")
            if verify_signature(ec384_signed, ec384_pub):
                test_pass("tsactl sign ES384")
            else:
                test_fail("tsactl sign ES384", "Verification returned False")

            ec384_signed_auto = sign_document(doc, ec384_priv, "test:ec384")
            ec384_auto_alg = ec384_signed_auto.get("signature", {}).get("algorithm")
            if ec384_auto_alg == "ES384" and verify_signature(ec384_signed_auto, ec384_pub):
                test_pass("tsactl sign ES384 auto")
            else:
                test_fail("tsactl sign ES384 auto", "Auto detection failed")
        except Exception as e:
            test_fail("tsactl sign multi-alg", str(e))


def test_tsactl_error_branches():
    """Exercise tsactl error paths and helpers for full coverage."""
    log("\n=== tsactl Error Branch Tests ===")

    try:
        import tools.tsactl as tsactl_cli
        import tools.tsactl_core as tsactl
    except ImportError as e:
        test_fail("tsactl import", str(e))
        return

    # canonicalize error branches
    for label, value in [
        ("NaN", float("nan")),
        ("Infinity", float("inf")),
        ("-Infinity", float("-inf")),
    ]:
        try:
            tsactl.canonicalize(value)
            test_fail(f"Canonicalize {label}", "Expected ValueError")
        except ValueError:
            test_pass(f"Canonicalize {label}")

    if tsactl.canonicalize(None) == "null":
        test_pass("Canonicalize null")
    else:
        test_fail("Canonicalize null", "Unexpected canonical null")

    if tsactl.canonicalize(1.2300) == "1.23":
        test_pass("Canonicalize float trimming")
    else:
        test_fail("Canonicalize float trimming", "Unexpected float format")

    if tsactl.canonicalize(1.0) == "1":
        test_pass("Canonicalize integral float")
    else:
        test_fail("Canonicalize integral float", "Unexpected float format")

    original_repr = getattr(tsactl, "repr", None)
    tsactl.repr = lambda _value: "1.0"
    try:
        if tsactl.canonicalize(1.5) == "1.0":
            test_pass("Canonicalize float dot trim")
        else:
            test_fail("Canonicalize float dot trim", "Unexpected float format")
    finally:
        if original_repr is None:
            delattr(tsactl, "repr")
        else:
            tsactl.repr = original_repr

    try:
        tsactl.canonicalize({1, 2})
        test_fail("Canonicalize unsupported", "Expected TypeError")
    except TypeError:
        test_pass("Canonicalize unsupported type")

    # compute_canonical_hash excludes signatures
    doc = {"a": 1, "signature": {"value": "test"}}
    hash_with_sig = tsactl.compute_canonical_hash(doc)
    hash_without_sig = tsactl.compute_canonical_hash({"a": 1})
    if hash_with_sig == hash_without_sig:
        test_pass("Canonical hash excludes signature")
    else:
        test_fail("Canonical hash excludes signature", "Signature affected hash")

    # schema path missing
    original_exists = Path.exists
    try:
        Path.exists = lambda self: False
        if tsactl.find_schema_path() is None:
            test_pass("Schema path missing")
        else:
            test_fail("Schema path missing", "Expected None")
        if tsactl.load_schema() is None:
            test_pass("Load schema missing")
        else:
            test_fail("Load schema missing", "Expected None")
    finally:
        Path.exists = original_exists

    # validate_schema: jsonschema not available
    original_jsonschema = tsactl.JSONSCHEMA_AVAILABLE
    tsactl.JSONSCHEMA_AVAILABLE = False
    try:
        errors = tsactl.validate_schema({}, {"type": "object"})
        if errors:
            test_pass("validate_schema without jsonschema")
        else:
            test_fail("validate_schema without jsonschema", "Expected error")
    finally:
        tsactl.JSONSCHEMA_AVAILABLE = original_jsonschema

    # validate_schema: invalid schema
    bad_schema = {"type": "object", "properties": {"a": {"type": "nope"}}}
    errors = tsactl.validate_schema({}, bad_schema)
    if errors and errors[0].startswith("Invalid schema"):
        test_pass("validate_schema invalid schema")
    else:
        test_fail("validate_schema invalid schema", "Expected invalid schema error")

    # validate_schema: invalid document produces errors
    schema_path = REPO_ROOT / "schema" / "tsa-v1.0.0.schema.json"
    with open(schema_path) as f:
        schema = json.load(f)
    errors = tsactl.validate_schema({}, schema)
    if errors:
        test_pass("validate_schema document errors")
    else:
        test_fail("validate_schema document errors", "Expected schema errors")

    # ValidationResult summary branches
    result = tsactl.ValidationResult()
    result.add_schema_error("schema error")
    result.add_semantic_error("semantic error")
    result.add_warning("warning")
    summary = result.summary()
    if "Schema Errors" in summary and "Semantic Errors" in summary and "Warnings" in summary:
        test_pass("ValidationResult summary")
    else:
        test_fail("ValidationResult summary", "Missing summary sections")

    # validate_semantics warnings/errors
    semantic_doc = {
        "tsa_version": "0.9.0",
        "published": "2025-01-02T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
        "affected": [{"status": "AFFECTED", "versions": {}}],
        "actions": [{"type": "WARN"}],
        "references": [],
        "severity": {},
    }
    sem_errors, sem_warnings = tsactl.validate_semantics(semantic_doc)
    if sem_errors and sem_warnings:
        test_pass("validate_semantics warnings/errors")
    else:
        test_fail("validate_semantics warnings/errors", "Expected warnings and errors")

    try:
        tsactl.validate_semantics({"published": "not-a-date", "modified": None})
        test_pass("validate_semantics invalid timestamps")
    except Exception as exc:
        test_fail("validate_semantics invalid timestamps", str(exc))

    no_affected_doc = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
        "affected": [{"status": "NOT_AFFECTED"}],
        "actions": [{"type": "UPDATE"}],
        "references": [{"type": "WEB"}],
        "severity": {"qualitative": "LOW"},
    }
    _, warnings = tsactl.validate_semantics(no_affected_doc)
    if any("No entries with AFFECTED status" in warn for warn in warnings):
        test_pass("validate_semantics no affected warning")
    else:
        test_fail("validate_semantics no affected warning", "Expected warning")

    if any("No BLOCK or WARN actions" in warn for warn in warnings):
        test_pass("validate_semantics no block/warn warning")
    else:
        test_fail("validate_semantics no block/warn warning", "Expected warning")

    if any("No CVSS score" in warn for warn in warnings):
        test_pass("validate_semantics no cvss warning")
    else:
        test_fail("validate_semantics no cvss warning", "Expected warning")

    # validate_tsa with missing schema
    original_load_schema = tsactl.load_schema
    tsactl.load_schema = lambda: None
    try:
        result = tsactl.validate_tsa(
            {
                "tsa_version": "1.0.0",
                "id": "TSA-TEST-2025-0001",
                "published": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "publisher": {"name": "Test", "namespace": "https://example.test"},
                "title": "Test",
                "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
                "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
            }
        )
        if result.warnings:
            test_pass("validate_tsa schema missing warning")
        else:
            test_fail("validate_tsa schema missing warning", "Expected warnings")
    finally:
        tsactl.load_schema = original_load_schema

    result = tsactl.validate_tsa({})
    if result.schema_errors:
        test_pass("validate_tsa schema errors")
    else:
        test_fail("validate_tsa schema errors", "Expected schema errors")

    semantic_error_path = REPO_ROOT / "test-vectors" / "tv01-minimal.tsa.json"
    with open(semantic_error_path) as handle:
        semantic_error_doc = json.load(handle)
    semantic_error_doc["published"] = "2025-01-02T00:00:00Z"
    semantic_error_doc["modified"] = "2025-01-01T00:00:00Z"
    result = tsactl.validate_tsa(semantic_error_doc)
    if result.semantic_errors:
        test_pass("validate_tsa semantic errors")
    else:
        test_fail("validate_tsa semantic errors", "Expected semantic errors")

    # cryptography missing branches
    original_crypto = tsactl.CRYPTO_AVAILABLE
    tsactl.CRYPTO_AVAILABLE = False
    try:
        try:
            tsactl.generate_keys("tmp/test")
            test_fail("generate_keys without crypto", "Expected RuntimeError")
        except RuntimeError:
            test_pass("generate_keys without crypto")

        try:
            tsactl.sign_document({"a": 1}, "missing", "id")
            test_fail("sign_document without crypto", "Expected RuntimeError")
        except RuntimeError:
            test_pass("sign_document without crypto")

        try:
            tsactl.verify_signature({"signature": {"algorithm": "Ed25519", "value": "a"}}, "x")
            test_fail("verify_signature without crypto", "Expected RuntimeError")
        except RuntimeError:
            test_pass("verify_signature without crypto")
    finally:
        tsactl.CRYPTO_AVAILABLE = original_crypto

    # verify_signature error branches
    try:
        tsactl.verify_signature({}, "missing")
        test_fail("verify_signature missing signature", "Expected ValueError")
    except ValueError:
        test_pass("verify_signature missing signature")

    try:
        tsactl.verify_signature({"signature": {"algorithm": "NOPE"}}, "missing")
        test_fail("verify_signature unsupported algorithm", "Expected ValueError")
    except ValueError:
        test_pass("verify_signature unsupported algorithm")

    # verify_signature key mismatch error branch
    with tempfile.TemporaryDirectory() as tmpdir:
        _, pub_path = tsactl.generate_keys(os.path.join(tmpdir, "sigtest"))
        try:
            tsactl.verify_signature(
                {"signature": {"algorithm": "RS256", "key_id": "x", "value": "AA=="}},
                pub_path,
            )
            test_fail("verify_signature key mismatch", "Expected ValueError")
        except ValueError as exc:
            if str(exc) == "Public key is not RSA":
                test_pass("verify_signature key mismatch")
            else:
                test_fail("verify_signature key mismatch", str(exc))

    if tsactl.CRYPTO_AVAILABLE:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        except ImportError as exc:
            test_fail("verify_signature algorithm imports", str(exc))
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                base_doc = {"tsa_version": "1.0.0", "id": "TSA-TEST-ALG"}
                canonical = tsactl.canonicalize(base_doc).encode("utf-8")

                rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                rsa_public = rsa_private.public_key()
                rsa_sig = rsa_private.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
                rsa_doc = dict(base_doc)
                rsa_doc["signature"] = {
                    "algorithm": "RS256",
                    "key_id": "test:rsa",
                    "value": base64.b64encode(rsa_sig).decode("ascii"),
                }
                rsa_pub_path = os.path.join(tmpdir, "rsa_pub.pem")
                with open(rsa_pub_path, "wb") as handle:
                    handle.write(
                        rsa_public.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    )

                # invalid RS256 signature path
                bad_rsa = json.loads(json.dumps(rsa_doc))
                bad_rsa["signature"]["value"] = base64.b64encode(b"\x00" * len(rsa_sig)).decode(
                    "ascii"
                )
                if tsactl.verify_signature(bad_rsa, rsa_pub_path) is False:
                    test_pass("verify_signature RS256 invalid")
                else:
                    test_fail("verify_signature RS256 invalid", "Expected False")

                # Ed25519 with RSA key mismatch
                ed_with_rsa = dict(base_doc)
                ed_with_rsa["signature"] = {
                    "algorithm": "Ed25519",
                    "key_id": "test:ed",
                    "value": base64.b64encode(rsa_sig).decode("ascii"),
                }
                try:
                    tsactl.verify_signature(ed_with_rsa, rsa_pub_path)
                    test_fail("verify_signature Ed25519 key mismatch", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Public key is not Ed25519":
                        test_pass("verify_signature Ed25519 key mismatch")
                    else:
                        test_fail("verify_signature Ed25519 key mismatch", str(exc))

                ec256_private = ec.generate_private_key(ec.SECP256R1())
                ec256_public = ec256_private.public_key()
                ec256_sig = ec256_private.sign(canonical, ec.ECDSA(hashes.SHA256()))
                ec256_doc = dict(base_doc)
                ec256_doc["signature"] = {
                    "algorithm": "ES256",
                    "key_id": "test:ec256",
                    "value": base64.b64encode(ec256_sig).decode("ascii"),
                }
                ec256_pub_path = os.path.join(tmpdir, "ec256_pub.pem")
                with open(ec256_pub_path, "wb") as handle:
                    handle.write(
                        ec256_public.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    )

                # invalid ES256 signature path
                bad_ec256 = json.loads(json.dumps(ec256_doc))
                bad_ec256["signature"]["value"] = base64.b64encode(b"\x00" * len(ec256_sig)).decode(
                    "ascii"
                )
                if tsactl.verify_signature(bad_ec256, ec256_pub_path) is False:
                    test_pass("verify_signature ES256 invalid")
                else:
                    test_fail("verify_signature ES256 invalid", "Expected False")

                # ES256 with RSA key mismatch
                es256_with_rsa = dict(base_doc)
                es256_with_rsa["signature"] = {
                    "algorithm": "ES256",
                    "key_id": "test:ec256",
                    "value": base64.b64encode(ec256_sig).decode("ascii"),
                }
                try:
                    tsactl.verify_signature(es256_with_rsa, rsa_pub_path)
                    test_fail("verify_signature ES256 key mismatch", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Public key is not P-256":
                        test_pass("verify_signature ES256 key mismatch")
                    else:
                        test_fail("verify_signature ES256 key mismatch", str(exc))

                ec384_private = ec.generate_private_key(ec.SECP384R1())
                ec384_public = ec384_private.public_key()
                ec384_sig = ec384_private.sign(canonical, ec.ECDSA(hashes.SHA384()))
                ec384_doc = dict(base_doc)
                ec384_doc["signature"] = {
                    "algorithm": "ES384",
                    "key_id": "test:ec384",
                    "value": base64.b64encode(ec384_sig).decode("ascii"),
                }
                ec384_pub_path = os.path.join(tmpdir, "ec384_pub.pem")
                with open(ec384_pub_path, "wb") as handle:
                    handle.write(
                        ec384_public.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    )

                # invalid ES384 signature path
                bad_ec384 = json.loads(json.dumps(ec384_doc))
                bad_ec384["signature"]["value"] = base64.b64encode(b"\x00" * len(ec384_sig)).decode(
                    "ascii"
                )
                if tsactl.verify_signature(bad_ec384, ec384_pub_path) is False:
                    test_pass("verify_signature ES384 invalid")
                else:
                    test_fail("verify_signature ES384 invalid", "Expected False")

                # ES384 with RSA key mismatch
                es384_with_rsa = dict(base_doc)
                es384_with_rsa["signature"] = {
                    "algorithm": "ES384",
                    "key_id": "test:ec384",
                    "value": base64.b64encode(ec384_sig).decode("ascii"),
                }
                try:
                    tsactl.verify_signature(es384_with_rsa, rsa_pub_path)
                    test_fail("verify_signature ES384 key mismatch", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Public key is not P-384":
                        test_pass("verify_signature ES384 key mismatch")
                    else:
                        test_fail("verify_signature ES384 key mismatch", str(exc))

                # ES256 with wrong curve (P-384)
                try:
                    tsactl.verify_signature(ec256_doc, ec384_pub_path)
                    test_fail("verify_signature ES256 wrong curve", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Public key is not P-256":
                        test_pass("verify_signature ES256 wrong curve")
                    else:
                        test_fail("verify_signature ES256 wrong curve", str(exc))

                # ES384 with wrong curve (P-256)
                try:
                    tsactl.verify_signature(ec384_doc, ec256_pub_path)
                    test_fail("verify_signature ES384 wrong curve", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Public key is not P-384":
                        test_pass("verify_signature ES384 wrong curve")
                    else:
                        test_fail("verify_signature ES384 wrong curve", str(exc))

    # invalid signature returns False
    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path, pub_path = tsactl.generate_keys(os.path.join(tmpdir, "sigtest"))
        signed = tsactl.sign_document({"tsa_version": "1.0.0"}, priv_path, "test:key")
        sig_bytes = base64.b64decode(signed["signature"]["value"])
        signed["signature"]["value"] = base64.b64encode(b"\x00" * len(sig_bytes)).decode("ascii")
        if tsactl.verify_signature(signed, pub_path) is False:
            test_pass("verify_signature invalid signature")
        else:
            test_fail("verify_signature invalid signature", "Expected False")

    # sign_document error branches
    if tsactl.CRYPTO_AVAILABLE:
        with tempfile.TemporaryDirectory() as tmpdir:
            base_doc = {"tsa_version": "1.0.0", "id": "TSA-TEST-ALG-ERR"}

            ed_priv, _ = tsactl.generate_keys(os.path.join(tmpdir, "ed"))
            rsa_priv, _ = tsactl.generate_keys(os.path.join(tmpdir, "rsa"), algorithm="RS256")
            es256_priv, _ = tsactl.generate_keys(os.path.join(tmpdir, "ec256"), algorithm="ES256")
            es384_priv, _ = tsactl.generate_keys(os.path.join(tmpdir, "ec384"), algorithm="ES384")

            try:
                tsactl.sign_document(base_doc, rsa_priv, "test:key", algorithm="Ed25519")
                test_fail("sign_document ed25519 mismatch", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Private key is not Ed25519":
                    test_pass("sign_document ed25519 mismatch")
                else:
                    test_fail("sign_document ed25519 mismatch", str(exc))

            try:
                tsactl.sign_document(base_doc, ed_priv, "test:key", algorithm="RS256")
                test_fail("sign_document rsa mismatch", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Private key is not RSA":
                    test_pass("sign_document rsa mismatch")
                else:
                    test_fail("sign_document rsa mismatch", str(exc))

            try:
                tsactl.sign_document(base_doc, ed_priv, "test:key", algorithm="ES256")
                test_fail("sign_document es256 mismatch", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Private key is not P-256":
                    test_pass("sign_document es256 mismatch")
                else:
                    test_fail("sign_document es256 mismatch", str(exc))

            try:
                tsactl.sign_document(base_doc, es384_priv, "test:key", algorithm="ES256")
                test_fail("sign_document es256 wrong curve", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Private key is not P-256":
                    test_pass("sign_document es256 wrong curve")
                else:
                    test_fail("sign_document es256 wrong curve", str(exc))

            try:
                tsactl.sign_document(base_doc, ed_priv, "test:key", algorithm="ES384")
                test_fail("sign_document es384 mismatch", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Private key is not P-384":
                    test_pass("sign_document es384 mismatch")
                else:
                    test_fail("sign_document es384 mismatch", str(exc))

            try:
                tsactl.sign_document(base_doc, es256_priv, "test:key", algorithm="ES384")
                test_fail("sign_document es384 wrong curve", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Private key is not P-384":
                    test_pass("sign_document es384 wrong curve")
                else:
                    test_fail("sign_document es384 wrong curve", str(exc))

            try:
                tsactl.sign_document(base_doc, ed_priv, "test:key", algorithm="NOPE")
                test_fail("sign_document unsupported algorithm", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Unsupported algorithm: NOPE":
                    test_pass("sign_document unsupported algorithm")
                else:
                    test_fail("sign_document unsupported algorithm", str(exc))

            try:
                tsactl.generate_keys(os.path.join(tmpdir, "bad"), algorithm="NOPE")
                test_fail("generate_keys unsupported algorithm", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Unsupported algorithm: NOPE":
                    test_pass("generate_keys unsupported algorithm")
                else:
                    test_fail("generate_keys unsupported algorithm", str(exc))

            original_generate = tsactl.rsa.generate_private_key
            try:

                def _assert_rsa_bits(public_exponent, key_size):
                    if key_size != 2048:
                        raise AssertionError(f"Expected rsa_bits 2048, got {key_size}")
                    return original_generate(public_exponent=public_exponent, key_size=key_size)

                tsactl.rsa.generate_private_key = _assert_rsa_bits
                tsactl.generate_keys(os.path.join(tmpdir, "rsa-default"), algorithm="RS256")
                test_pass("generate_keys rsa default bits")
            except AssertionError as exc:
                test_fail("generate_keys rsa default bits", str(exc))
            finally:
                tsactl.rsa.generate_private_key = original_generate

            try:
                bad_ec_key = tsactl.ec.generate_private_key(tsactl.ec.SECP521R1())
                tsactl._detect_signing_algorithm(bad_ec_key)
                test_fail("detect_signing_algorithm unsupported curve", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Unsupported EC curve for signing":
                    test_pass("detect_signing_algorithm unsupported curve")
                else:
                    test_fail("detect_signing_algorithm unsupported curve", str(exc))

            try:
                tsactl._detect_signing_algorithm(object())
                test_fail("detect_signing_algorithm unsupported key", "Expected ValueError")
            except ValueError as exc:
                if str(exc) == "Unsupported private key type for signing":
                    test_pass("detect_signing_algorithm unsupported key")
                else:
                    test_fail("detect_signing_algorithm unsupported key", str(exc))

    # cmd_* error branches
    class Args:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    original_crypto = tsactl.CRYPTO_AVAILABLE
    tsactl.CRYPTO_AVAILABLE = False
    try:
        if (
            tsactl_cli.cmd_sign(
                Args(
                    tsa_file="missing",
                    key_file="missing",
                    key_id="x",
                    output=None,
                    algorithm="Ed25519",
                )
            )
            == 1
        ):
            test_pass("cmd_sign without crypto")
        else:
            test_fail("cmd_sign without crypto", "Expected return 1")
        if tsactl_cli.cmd_verify(Args(tsa_file="missing", pub_key="missing")) == 1:
            test_pass("cmd_verify without crypto")
        else:
            test_fail("cmd_verify without crypto", "Expected return 1")
        if (
            tsactl_cli.cmd_generate_keys(Args(prefix="missing", algorithm="Ed25519", rsa_bits=2048))
            == 1
        ):
            test_pass("cmd_generate_keys without crypto")
        else:
            test_fail("cmd_generate_keys without crypto", "Expected return 1")
    finally:
        tsactl.CRYPTO_AVAILABLE = original_crypto

    # cmd_verify exception branch
    original_verify_signature = tsactl.verify_signature
    tsactl.verify_signature = lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception("boom"))
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(json.dumps({"signature": {"algorithm": "Ed25519", "value": "AA=="}}))
        if tsactl_cli.cmd_verify(Args(tsa_file=tmp.name, pub_key="missing")) == 1:
            test_pass("cmd_verify exception")
        else:
            test_fail("cmd_verify exception", "Expected return 1")
    finally:
        tsactl.verify_signature = original_verify_signature
        os.unlink(tmp.name)

    # cmd_verify invalid signature branch
    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path, pub_path = tsactl.generate_keys(os.path.join(tmpdir, "sigtest"))
        signed = tsactl.sign_document({"tsa_version": "1.0.0"}, priv_path, "test:key")
        sig_bytes = base64.b64decode(signed["signature"]["value"])
        signed["signature"]["value"] = base64.b64encode(b"\x00" * len(sig_bytes)).decode("ascii")
        signed_path = os.path.join(tmpdir, "signed.json")
        with open(signed_path, "w") as handle:
            json.dump(signed, handle)
        if tsactl_cli.cmd_verify(Args(tsa_file=signed_path, pub_key=pub_path)) == 1:
            test_pass("cmd_verify invalid signature")
        else:
            test_fail("cmd_verify invalid signature", "Expected return 1")

    # cmd_match no matches
    with (
        tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_adv,
        tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_inv,
    ):
        tmp_adv.write(
            json.dumps(
                {
                    "tsa_version": "1.0.0",
                    "id": "TSA-TEST-2025-0002",
                    "published": "2025-01-01T00:00:00Z",
                    "modified": "2025-01-01T00:00:00Z",
                    "publisher": {"name": "Test", "namespace": "https://example.test"},
                    "title": "Test",
                    "affected": [
                        {"tool": {"name": "demo", "registry": "npm"}, "status": "AFFECTED"}
                    ],
                    "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
                }
            )
        )
        tmp_inv.write(json.dumps([{"name": "other", "version": "1.0.0", "registry": "npm"}]))
    try:
        if tsactl_cli.cmd_match(Args(tsa_file=tmp_adv.name, inventory=tmp_inv.name)) == 0:
            test_pass("cmd_match no matches")
        else:
            test_fail("cmd_match no matches", "Expected return 0")
    finally:
        os.unlink(tmp_adv.name)
        os.unlink(tmp_inv.name)

    advisory = {
        "id": "TSA-TEST-2025-0102",
        "severity": {"qualitative": "LOW"},
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"last_affected": "1.0.0"},
                "status": "AFFECTED",
            }
        ],
    }
    if not tsactl.match_advisory(
        advisory, [{"name": "demo", "version": "1.1.0", "registry": "npm"}]
    ):
        test_pass("match_advisory last_affected exclusion")
    else:
        test_fail("match_advisory last_affected exclusion", "Expected no matches")

    advisory["affected"][0]["status"] = "UNAFFECTED"
    if not tsactl.match_advisory(
        advisory, [{"name": "demo", "version": "0.9.0", "registry": "npm"}]
    ):
        test_pass("match_advisory status skip")
    else:
        test_fail("match_advisory status skip", "Expected no matches")

    advisory["affected"][0]["status"] = "AFFECTED"
    if not tsactl.match_advisory(
        advisory, [{"name": "demo", "version": "0.9.0", "registry": "pypi"}]
    ):
        test_pass("match_advisory registry mismatch")
    else:
        test_fail("match_advisory registry mismatch", "Expected no matches")

    # main help branch
    argv_backup = list(sys.argv)
    try:
        sys.argv = ["tsactl"]
        if tsactl_cli.main() == 1:
            test_pass("tsactl main help")
        else:
            test_fail("tsactl main help", "Expected return 1")
    finally:
        sys.argv = argv_backup

    # __main__ execution
    argv_backup = list(sys.argv)
    try:
        sys.argv = ["tsactl"]
        try:
            runpy.run_path(str(resolve_tool_script("tsactl.py")), run_name="__main__")
        except SystemExit:
            test_pass("tsactl __main__")
    finally:
        sys.argv = argv_backup


def test_tsactl_schema_error_ordering():
    """Ensure schema errors are sorted deterministically by path."""
    log("\n=== tsactl Schema Error Ordering Tests ===")

    try:
        import tools.tsactl_core as tsactl
    except ImportError as e:
        test_fail("tsactl schema ordering import", str(e))
        return

    if not getattr(tsactl, "JSONSCHEMA_AVAILABLE", False):
        test_fail("tsactl schema ordering", "jsonschema not available")
        return

    class DummyError:
        def __init__(self, path, message):
            self.absolute_path = path
            self.message = message

    class DummyValidator:
        def __init__(self, *_args, **_kwargs):
            return None

        @staticmethod
        def check_schema(_schema):
            return None

        def iter_errors(self, _doc):
            return [
                DummyError(["b"], "err-b"),
                DummyError(["a"], "err-a"),
            ]

    original = tsactl.Draft202012Validator
    tsactl.Draft202012Validator = DummyValidator
    try:
        errors = tsactl.validate_schema({"a": 1}, {"type": "object"})
        expected = ["[a] err-a", "[b] err-b"]
        if errors == expected:
            test_pass("validate_schema error ordering")
        else:
            test_fail("validate_schema error ordering", f"Expected {expected}, got {errors}")
    finally:
        tsactl.Draft202012Validator = original


def test_tsactl_semantics_positive():
    """Ensure semantic validation produces no warnings for a well-formed doc."""
    log("\n=== tsactl Semantics Positive Tests ===")

    try:
        import tools.tsactl_core as tsactl
    except ImportError as e:
        test_fail("tsactl semantics import", str(e))
        return

    good_doc = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "1.2.0"},
            }
        ],
        "actions": [{"type": "BLOCK", "message": "Block it"}],
        "references": [{"type": "CVE", "id": "CVE-2025-0001", "url": "https://example.test/cve"}],
        "severity": {
            "cvss_v3": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            }
        },
    }

    errors, warnings = tsactl.validate_semantics(good_doc)
    if not errors and not warnings:
        test_pass("validate_semantics clean doc")
    else:
        test_fail("validate_semantics clean doc", f"errors={errors}, warnings={warnings}")


def test_tsactl_semantics_edge_cases():
    """Cover semantic validation edge cases for version constraints and CVSS."""
    log("\n=== tsactl Semantics Edge Tests ===")

    try:
        import tools.tsactl_core as tsactl
    except ImportError as e:
        test_fail("tsactl semantics edge import", str(e))
        return

    doc_fixed = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {
                "status": "AFFECTED",
                "tool": {"name": "demo"},
                "versions": {"fixed": "1.2.0"},
            }
        ],
        "actions": [{"type": "BLOCK", "message": "Block it"}],
        "references": [{"type": "CVE", "id": "CVE-2025-0001"}],
        "severity": {"cvss_v3": {"vector": "CVSS:3.1/AV:N"}},
    }
    errors, warnings = tsactl.validate_semantics(doc_fixed)
    if not errors and "no version constraints" not in " ".join(warnings):
        test_pass("validate_semantics fixed version ok")
    else:
        test_fail("validate_semantics fixed version ok", f"errors={errors}, warnings={warnings}")

    doc_range = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {
                "status": "AFFECTED",
                "tool": {"name": "demo"},
                "versions": {"affected_range": ">=1.0.0 <2.0.0"},
            }
        ],
        "actions": [{"type": "BLOCK", "message": "Block it"}],
        "references": [{"type": "ADVISORY", "url": "https://example.test"}],
        "severity": {"cvss_v3": {"vector": "CVSS:3.1/AV:N"}},
    }
    errors, warnings = tsactl.validate_semantics(doc_range)
    if not errors and "no version constraints" not in " ".join(warnings):
        test_pass("validate_semantics affected_range ok")
    else:
        test_fail("validate_semantics affected_range ok", f"errors={errors}, warnings={warnings}")

    doc_cvss_v4 = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {
                "status": "AFFECTED",
                "tool": {"name": "demo"},
                "versions": {"introduced": "1.0.0"},
            }
        ],
        "actions": [{"type": "BLOCK", "message": "Block it"}],
        "references": [{"type": "CVE", "id": "CVE-2025-0002"}],
        "severity": {"cvss_v4": {"vector": "CVSS:4.0/AV:N"}},
    }
    errors, warnings = tsactl.validate_semantics(doc_cvss_v4)
    if not errors and not any("No CVSS score" in warn for warn in warnings):
        test_pass("validate_semantics cvss_v4 ok")
    else:
        test_fail("validate_semantics cvss_v4 ok", f"errors={errors}, warnings={warnings}")


def test_tsactl_match_bounds():
    """Exercise match_advisory bounds logic."""
    log("\n=== tsactl Match Bounds Tests ===")

    try:
        import tools.tsactl_core as tsactl
    except ImportError as e:
        test_fail("tsactl match import", str(e))
        return

    tsa_doc = {
        "id": "TSA-TEST-2025-9999",
        "severity": {"qualitative": "HIGH"},
        "affected": [
            {
                "tool": {"name": "intro", "registry": "npm"},
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
                "status": "AFFECTED",
                "impact_statement": "Impact",
            },
            {
                "tool": {"name": "last", "registry": "npm"},
                "versions": {"last_affected": "1.4.0"},
                "status": "AFFECTED",
            },
            {
                "tool": {"name": "range", "registry": "npm"},
                "versions": {"affected_range": ">=3.0.0 <3.1.0"},
                "status": "AFFECTED",
            },
            {
                "tool": {"name": "skip", "registry": "npm"},
                "versions": {"introduced": "0.1.0"},
                "status": "NOT_AFFECTED",
            },
        ],
    }

    inventory = [
        {"name": "intro", "version": "1.5.0", "registry": "npm"},
        {"name": "intro", "version": "2.0.0", "registry": "npm"},
        {"name": "last", "version": "1.4.0", "registry": "npm"},
        {"name": "last", "version": "1.4.1", "registry": "npm"},
        {"name": "range", "version": "3.0.5", "registry": "npm"},
        {"name": "range", "version": "3.1.0", "registry": "npm"},
        {"name": "skip", "version": "0.2.0", "registry": "npm"},
    ]

    matches = tsactl.match_advisory(tsa_doc, inventory)
    match_set = {(m["tool"], m["version"]) for m in matches}
    expected = {("intro", "1.5.0"), ("last", "1.4.0"), ("range", "3.0.5")}

    if match_set == expected:
        test_pass("match_advisory bounds")
    else:
        test_fail("match_advisory bounds", f"Expected {expected}, got {match_set}")

    intro_match = next((m for m in matches if m["tool"] == "intro"), None)
    if intro_match and intro_match.get("fixed_version") == "2.0.0":
        test_pass("match_advisory fixed_version")
    else:
        test_fail("match_advisory fixed_version", "Expected fixed_version=2.0.0")

    missing_name_doc = {
        "id": "TSA-MISSING-NAME",
        "affected": [{"status": "AFFECTED", "versions": {}}],
    }
    missing_inventory = [{"version": "1.0.0", "registry": "npm"}]
    if tsactl.match_advisory(missing_name_doc, missing_inventory) == []:
        test_pass("match_advisory missing name")
    else:
        test_fail("match_advisory missing name", "Expected no matches when name missing")

    odd_name_doc = {
        "id": "TSA-ODD-NAME",
        "affected": [{"tool": {"name": "XXXX"}, "status": "AFFECTED", "versions": {}}],
    }
    if tsactl.match_advisory(odd_name_doc, missing_inventory) == []:
        test_pass("match_advisory missing name default")
    else:
        test_fail("match_advisory missing name default", "Expected no matches when name missing")


def test_tsactl_missing_imports():
    """Load tsactl with blocked imports to cover ImportError branches."""
    log("\n=== tsactl Import Error Tests ===")

    module = load_module_from_path(
        "tsactl_no_deps",
        TOOLS_ROOT / "tools" / "tsactl_core.py",
        blocked_imports=["jsonschema", "cryptography"],
    )

    if module.JSONSCHEMA_AVAILABLE is False and module.CRYPTO_AVAILABLE is False:
        test_pass("tsactl missing deps flags")
    else:
        test_fail("tsactl missing deps flags", "Expected missing deps flags")

    errors = module.validate_schema({}, {"type": "object"})
    if errors:
        test_pass("tsactl validate_schema missing deps")
    else:
        test_fail("tsactl validate_schema missing deps", "Expected error list")

    try:
        module.generate_keys("prefix")
        test_fail("tsactl generate_keys missing deps", "Expected RuntimeError")
    except RuntimeError:
        test_pass("tsactl generate_keys missing deps")


def test_tsactl_version_helpers():
    """Exercise semver helpers and range parsing branches."""
    log("\n=== tsactl Version Helper Tests ===")

    try:
        import tools.tsactl as tsactl
        import tools.tsactl_core as tsactl_core
    except ImportError as e:
        test_fail("tsactl import", str(e))
        return

    if tsactl._parse_semver("1.2.3") and tsactl._parse_semver("v1.2.3-beta.1"):
        test_pass("parse_semver valid")
    else:
        test_fail("parse_semver valid", "Expected parse result")

    if tsactl._parse_semver("not-a-version") is None:
        test_pass("parse_semver invalid")
    else:
        test_fail("parse_semver invalid", "Expected None")

    if tsactl._compare_prerelease([], []) == 0:
        test_pass("compare_prerelease empty")
    else:
        test_fail("compare_prerelease empty", "Expected equal")

    if tsactl._compare_prerelease([], [(True, 1)]) > 0:
        test_pass("compare_prerelease release greater")
    else:
        test_fail("compare_prerelease release greater", "Expected release > prerelease")

    if tsactl._compare_prerelease([(True, 1)], []) < 0:
        test_pass("compare_prerelease prerelease less")
    else:
        test_fail("compare_prerelease prerelease less", "Expected prerelease < release")

    if tsactl._compare_prerelease([(True, 1)], [(False, "a")]) < 0:
        test_pass("compare_prerelease numeric < string")
    else:
        test_fail("compare_prerelease numeric < string", "Expected numeric < string")

    if tsactl._compare_prerelease([(False, "a")], [(True, 1)]) > 0:
        test_pass("compare_prerelease string > numeric")
    else:
        test_fail("compare_prerelease string > numeric", "Expected string > numeric")

    if tsactl._compare_prerelease([(False, "a")], [(False, "b")]) < 0:
        test_pass("compare_prerelease lexicographic")
    else:
        test_fail("compare_prerelease lexicographic", "Expected a < b")

    if tsactl._compare_prerelease([(True, 1)], [(True, 2)]) < 0:
        test_pass("compare_prerelease numeric compare")
    else:
        test_fail("compare_prerelease numeric compare", "Expected 1 < 2")

    if tsactl_core._compare_prerelease([(True, 2)], [(True, 1)]) == 1:
        test_pass("compare_prerelease numeric greater")
    else:
        test_fail("compare_prerelease numeric greater", "Expected 2 > 1")

    if tsactl._compare_prerelease([(False, "b")], [(False, "a")]) == 1:
        test_pass("compare_prerelease string greater")
    else:
        test_fail("compare_prerelease string greater", "Expected exact return of 1")

    if tsactl._compare_prerelease([(True, 1)], [(True, 1), (True, 2)]) < 0:
        test_pass("compare_prerelease length")
    else:
        test_fail("compare_prerelease length", "Expected shorter < longer")

    if tsactl._compare_prerelease([(True, 1), (True, 2)], [(True, 1)]) > 0:
        test_pass("compare_prerelease length greater")
    else:
        test_fail("compare_prerelease length greater", "Expected longer > shorter")

    if tsactl.compare_versions("1.2.3", "1.2.3") == 0:
        test_pass("compare_versions equal")
    else:
        test_fail("compare_versions equal", "Expected 0")

    if tsactl.compare_versions("1.2.3", "1.2.4") < 0:
        test_pass("compare_versions semver")
    else:
        test_fail("compare_versions semver", "Expected v1 < v2")

    if tsactl.compare_versions("1.2.3-alpha", "1.2.3") < 0:
        test_pass("compare_versions prerelease")
    else:
        test_fail("compare_versions prerelease", "Expected prerelease < release")

    if tsactl.compare_versions("1.0.0", "1.0.0-beta") > 0:
        test_pass("compare_versions release > prerelease")
    else:
        test_fail("compare_versions release > prerelease", "Expected release > prerelease")

    if tsactl.compare_versions("1.0.0-2", "1.0.0-1") == 1:
        test_pass("compare_versions prerelease greater exact")
    else:
        test_fail("compare_versions prerelease greater exact", "Expected exact return of 1")

    if tsactl.compare_versions("release-2", "release-10") < 0:
        test_pass("compare_versions fallback <")
    else:
        test_fail("compare_versions fallback <", "Expected release-2 < release-10")

    if tsactl.compare_versions("release-10", "release-2") > 0:
        test_pass("compare_versions fallback >")
    else:
        test_fail("compare_versions fallback >", "Expected release-10 > release-2")

    if tsactl.compare_versions("release-1", "release-1") == 0:
        test_pass("compare_versions fallback =")
    else:
        test_fail("compare_versions fallback =", "Expected equality")

    if tsactl.compare_versions("1.2", "1.2.0") == 0:
        test_pass("compare_versions missing patch =")
    else:
        test_fail("compare_versions missing patch =", "Expected equality")

    if tsactl.compare_versions("1.2.0", "1.2") == 0:
        test_pass("compare_versions missing patch reversed =")
    else:
        test_fail("compare_versions missing patch reversed =", "Expected equality")

    if tsactl.version_in_range("1.2.3", "") is False:
        test_pass("version_in_range empty")
    else:
        test_fail("version_in_range empty", "Expected False")

    checks = [
        (">=1.2.3", "1.2.3", True),
        (">1.2.3", "1.2.3", False),
        ("<1.2.3", "1.2.2", True),
        ("<=1.2.3", "1.2.3", True),
        ("<=1.2.3", "2.0.0", False),
        ("=1.2.3", "1.2.3", True),
        ("=1.2.3", "1.2.4", False),
        ("1.2.3", "1.2.3", True),
        ("1.2.3", "1.2.4", False),
    ]
    for range_expr, version, expected in checks:
        if tsactl.version_in_range(version, range_expr) == expected:
            test_pass(f"version_in_range {range_expr}")
        else:
            test_fail(f"version_in_range {range_expr}", f"Expected {expected}")

    if tsactl.version_in_range("1.2.3", ">=1.0.0, <2.0.0") is True:
        test_pass("version_in_range comma")
    else:
        test_fail("version_in_range comma", "Expected True")

    class _RangeStub:
        def replace(self, *_args, **_kwargs):
            return self

        def split(self):
            return ["", ">=1.0.0"]

    original_re_sub = tsactl.re.sub
    tsactl.re.sub = lambda *_args, **_kwargs: _RangeStub()
    try:
        if tsactl.version_in_range("1.0.0", ">=1.0.0") is True:
            test_pass("version_in_range empty part")
        else:
            test_fail("version_in_range empty part", "Expected True")
    finally:
        tsactl.re.sub = original_re_sub


# =============================================================================
# Version Matching Tests
# =============================================================================


def test_version_matching_bounds():
    """Test introduced/fixed/last_affected bounds and range normalization."""
    log("\n=== Version Matching Bounds Tests ===")

    try:
        from tools.tsactl_core import match_advisory
        from tools.tsa_registry_sdk import TSARegistry
    except ImportError as e:
        test_fail("Version matching imports", str(e))
        return

    advisory = {
        "tsa_version": "1.0.0",
        "id": "TSA-TEST-0001",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Version bounds test",
        "affected": [
            {
                "tool": {"name": "demo-tool", "registry": "npm"},
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
                "status": "AFFECTED",
            }
        ],
        "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
    }

    inventory = [
        {"name": "demo-tool", "version": "0.9.9", "registry": "npm"},
        {"name": "demo-tool", "version": "1.0.0", "registry": "npm"},
        {"name": "demo-tool", "version": "1.5.0", "registry": "npm"},
        {"name": "demo-tool", "version": "2.0.0", "registry": "npm"},
    ]

    matches = match_advisory(advisory, inventory)
    matched_versions = sorted(m["version"] for m in matches)
    if matched_versions == ["1.0.0", "1.5.0"]:
        test_pass("tsactl respects introduced/fixed bounds")
    else:
        test_fail("tsactl version bounds", f"Got {matched_versions}")

    # Range normalization with commas
    advisory_range = {
        **advisory,
        "affected": [
            {
                "tool": {"name": "demo-tool", "registry": "npm"},
                "versions": {"affected_range": ">=1.0.0, <2.0.0"},
                "status": "AFFECTED",
            }
        ],
    }
    matches = match_advisory(advisory_range, inventory)
    matched_versions = sorted(m["version"] for m in matches)
    if matched_versions == ["1.0.0", "1.5.0"]:
        test_pass("tsactl normalizes range commas")
    else:
        test_fail("tsactl range normalization", f"Got {matched_versions}")

    # SDK bounds check
    registry = TSARegistry()
    registry.add_advisory(advisory)
    if (
        not registry.check_package("demo-tool", "0.9.9", "npm").blocked
        and registry.check_package("demo-tool", "1.5.0", "npm").warnings
    ):
        test_pass("SDK respects introduced/fixed bounds")
    else:
        test_fail("SDK version bounds", "Unexpected bounds behavior")

    advisory_exact = {
        **advisory,
        "id": "TSA-TEST-0002",
        "actions": [
            {
                "type": "WARN",
                "urgency": "LOW",
                "condition": "1.0.0",
                "message": "Exact match",
            }
        ],
    }
    registry = TSARegistry()
    registry.add_advisory(advisory_exact)
    if (
        registry.check_package("demo-tool", "1.0.0", "npm").warnings
        and not registry.check_package("demo-tool", "1.5.0", "npm").warnings
    ):
        test_pass("SDK exact version condition")
    else:
        test_fail("SDK exact version condition", "Condition matched unexpected versions")

    prerelease_advisory = {
        "tsa_version": "1.0.0",
        "id": "TSA-TEST-0003",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Prerelease bounds test",
        "affected": [
            {
                "tool": {"name": "demo-tool", "registry": "npm"},
                "versions": {"introduced": "1.0.0-beta.1", "fixed": "1.0.0"},
                "status": "AFFECTED",
            }
        ],
        "actions": [{"type": "WARN", "urgency": "LOW", "message": "Prerelease test"}],
    }

    prerelease_inventory = [
        {"name": "demo-tool", "version": "1.0.0-beta.1", "registry": "npm"},
        {"name": "demo-tool", "version": "1.0.0-beta.2", "registry": "npm"},
        {"name": "demo-tool", "version": "1.0.0", "registry": "npm"},
    ]
    prerelease_matches = match_advisory(prerelease_advisory, prerelease_inventory)
    prerelease_versions = {m["version"] for m in prerelease_matches}
    if prerelease_versions == {"1.0.0-beta.1", "1.0.0-beta.2"}:
        test_pass("Prerelease bounds match")
    else:
        test_fail("Prerelease bounds match", f"Unexpected matches: {prerelease_versions}")

    prerelease_range = {
        **prerelease_advisory,
        "id": "TSA-TEST-0004",
        "affected": [
            {
                "tool": {"name": "demo-tool", "registry": "npm"},
                "versions": {"affected_range": ">=1.0.0-beta.1 <1.0.0"},
                "status": "AFFECTED",
            }
        ],
    }
    prerelease_matches_range = match_advisory(prerelease_range, prerelease_inventory)
    prerelease_versions_range = {m["version"] for m in prerelease_matches_range}
    if prerelease_versions_range == {"1.0.0-beta.1", "1.0.0-beta.2"}:
        test_pass("Prerelease range match")
    else:
        test_fail(
            "Prerelease range match",
            f"Unexpected matches: {prerelease_versions_range}",
        )

    registry = TSARegistry()
    registry.add_advisory(prerelease_advisory)
    if (
        registry.check_package("demo-tool", "1.0.0-beta.2", "npm").advisories
        and not registry.check_package("demo-tool", "1.0.0", "npm").advisories
    ):
        test_pass("SDK prerelease match")
    else:
        test_fail("SDK prerelease match", "Unexpected prerelease match behavior")


# =============================================================================
# Converter and Feed Tests
# =============================================================================


def test_osv_converter_roundtrip():
    """Test TSA -> OSV conversion includes expected fields."""
    log("\n=== OSV Converter Tests ===")

    try:
        from tools.osv_converter import osv_to_tsa, tsa_to_osv
    except ImportError as e:
        test_fail("OSV converter import", str(e))
        return

    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-9999",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Converter test advisory",
        "severity": {
            "cvss_v3": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            }
        },
        "affected": [
            {
                "tool": {"name": "demo-tool", "registry": "npm"},
                "versions": {"introduced": "1.0.0", "fixed": "1.1.0"},
                "status": "AFFECTED",
            }
        ],
        "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
    }

    osv = tsa_to_osv(tsa_doc)
    if osv.get("database_specific", {}).get("tsa_id") == "TSA-2025-9999":
        test_pass("tsa_to_osv preserves tsa_id")
    else:
        test_fail("tsa_to_osv tsa_id", "Missing database_specific.tsa_id")

    tsa_back = osv_to_tsa(osv)
    if tsa_back.get("id") == "TSA-2025-9999":
        test_pass("osv_to_tsa restores TSA id")
    else:
        test_fail("osv_to_tsa id", f"Unexpected id {tsa_back.get('id')}")

    if tsa_back.get("title") == tsa_doc["title"] and tsa_back.get("affected"):
        test_pass("osv_to_tsa roundtrip fields")
    else:
        test_fail("osv_to_tsa roundtrip", "Missing title or affected entries")

    osv_doc = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Imported OSV advisory",
        "published": "2025-01-01T00:00:00Z",
    }
    tsa_from_osv = osv_to_tsa(osv_doc)
    if (
        tsa_from_osv.get("related_vulnerabilities")
        and tsa_from_osv["related_vulnerabilities"][0].get("id") == "GHSA-aaaa-bbbb-cccc"
    ):
        test_pass("osv_to_tsa preserves OSV id as related_vulnerability")
    else:
        test_fail("osv_to_tsa related_vulnerability", "Missing OSV id linkage")

    if tsa_from_osv.get("references") and any(
        r.get("url") == "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"
        for r in tsa_from_osv["references"]
    ):
        test_pass("osv_to_tsa adds OSV reference")
    else:
        test_fail("osv_to_tsa reference", "Missing OSV advisory reference")


def test_osv_converter_edge_cases():
    """Exercise remaining OSV converter branches."""
    log("\n=== OSV Converter Edge Tests ===")

    try:
        import tools.osv_converter as oc
    except ImportError as e:
        test_fail("OSV converter import", str(e))
        return

    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-0100",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "withdrawn": "2025-01-03T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Edge advisory",
        "description": "Detailed description",
        "severity": {
            "cvss_v4": {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "score": 9.8},
            "cvss_v3": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            },
        },
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm", "purl": "pkg:npm/demo@1.0.0"},
                "versions": {"introduced": "1.0.0", "fixed": "1.2.0"},
                "status": "AFFECTED",
                "capabilities_abused": ["filesystem.read"],
                "semantic_drift": {"original": "safe", "current": "unsafe", "impact": "HIGH"},
                "attack_context": {"requires_agent_execution": True},
                "impact_statement": "Impact",
            },
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"affected_range": ">=1.0.0 <1.1.0"},
                "status": "AFFECTED",
            },
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"affected_range": ">=1 <2"},
                "status": "AFFECTED",
            },
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"last_affected": "0.9.9"},
                "status": "AFFECTED",
            },
        ],
        "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
        "references": [
            {"type": "CVE", "id": "CVE-2025-0001", "url": "https://example.test/cve"},
            {"type": "WEB", "url": "https://example.test"},
        ],
        "related_vulnerabilities": [{"id": "CVE-2025-0002"}],
        "credits": [{"name": "Alice", "type": "FINDER", "contact": "alice@example.test"}],
    }

    osv = oc.tsa_to_osv(tsa_doc)
    if osv.get("withdrawn") and osv.get("details"):
        test_pass("tsa_to_osv withdrawn/details")
    else:
        test_fail("tsa_to_osv withdrawn/details", "Missing withdrawn/details")

    if osv.get("severity") and len(osv["severity"]) == 2:
        test_pass("tsa_to_osv severity mapping")
    else:
        test_fail("tsa_to_osv severity mapping", "Expected CVSS_V3/V4 entries")

    if osv.get("aliases") and "CVE-2025-0002" in osv["aliases"]:
        test_pass("tsa_to_osv aliases from related_vulnerabilities")
    else:
        test_fail("tsa_to_osv aliases", "Missing related vulnerability alias")

    if osv.get("credits") and osv["credits"][0].get("contact"):
        test_pass("tsa_to_osv credits contact")
    else:
        test_fail("tsa_to_osv credits contact", "Missing contact field")

    osv_doc = {
        "id": "OSV-2025-0001",
        "published": "2025-01-01T00:00:00Z",
        "withdrawn": "2025-02-01T00:00:00Z",
        "summary": "OSV summary",
        "details": "OSV details",
        "severity": [
            {
                "type": "CVSS_V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "score": "bad",
            },
            {
                "type": "CVSS_V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "score": "9.8",
            },
            {
                "type": "CVSS_V3",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": "x",
            },
        ],
        "affected": [
            {
                "package": {"name": "demo", "ecosystem": "npm", "purl": "pkg:npm/demo@1.0.0"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                    }
                ],
                "database_specific": {
                    "capabilities_abused": ["filesystem.write"],
                    "semantic_drift": {"original": "safe", "current": "unsafe", "impact": "HIGH"},
                    "attack_context": {"requires_agent_execution": True},
                    "impact_statement": "Impact",
                },
            },
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"last_affected": "0.9.9"}],
                    }
                ],
            },
        ],
        "references": [{"type": "PACKAGE", "url": "https://example.test/pkg"}],
        "aliases": ["CVE-2025-1234"],
        "credits": [{"name": "Bob", "type": "OTHER", "contact": ["bob@example.test"]}],
    }

    tsa_from_osv = oc.osv_to_tsa(osv_doc, tsa_id="TSA-2025-1111")
    if tsa_from_osv.get("withdrawn") and tsa_from_osv.get("description"):
        test_pass("osv_to_tsa withdrawn/details")
    else:
        test_fail("osv_to_tsa withdrawn/details", "Missing withdrawn/details")

    if tsa_from_osv.get("severity") and "cvss_v4" in tsa_from_osv["severity"]:
        test_pass("osv_to_tsa severity mapping")
    else:
        test_fail("osv_to_tsa severity mapping", "Missing severity mapping")

    if tsa_from_osv.get("affected") and tsa_from_osv["affected"][0].get("versions"):
        test_pass("osv_to_tsa affected mapping")
    else:
        test_fail("osv_to_tsa affected mapping", "Missing affected versions")

    if tsa_from_osv.get("references") and any(
        ref.get("type") == "WEB" for ref in tsa_from_osv["references"]
    ):
        test_pass("osv_to_tsa references mapping")
    else:
        test_fail("osv_to_tsa references mapping", "Missing references mapping")

    if tsa_from_osv.get("credits") and tsa_from_osv["credits"][0].get("contact"):
        test_pass("osv_to_tsa credits mapping")
    else:
        test_fail("osv_to_tsa credits mapping", "Missing credits contact")

    empty_tsa = oc.osv_to_tsa({"id": "GHSA-0000-0000-0000"})
    if empty_tsa.get("affected") and empty_tsa["affected"][0]["tool"]["name"] == "unknown":
        test_pass("osv_to_tsa default affected")
    else:
        test_fail("osv_to_tsa default affected", "Expected unknown affected entry")

    # Helper mappings
    if oc._registry_to_ecosystem("unknown") == "unknown":
        test_pass("registry_to_ecosystem fallback")
    else:
        test_fail("registry_to_ecosystem fallback", "Unexpected mapping")

    if oc._ecosystem_to_registry("UnknownEco") == "unknowneco":
        test_pass("ecosystem_to_registry fallback")
    else:
        test_fail("ecosystem_to_registry fallback", "Unexpected mapping")

    if oc._ref_type_to_osv("NONSTANDARD") == "WEB":
        test_pass("ref_type_to_osv fallback")
    else:
        test_fail("ref_type_to_osv fallback", "Unexpected mapping")

    if oc._osv_ref_type_to_tsa("NONSTANDARD") == "OTHER":
        test_pass("osv_ref_type_to_tsa fallback")
    else:
        test_fail("osv_ref_type_to_tsa fallback", "Unexpected mapping")

    if oc._credit_type_to_osv("NONSTANDARD") == "OTHER":
        test_pass("credit_type_to_osv fallback")
    else:
        test_fail("credit_type_to_osv fallback", "Unexpected mapping")

    if oc._osv_credit_type_to_tsa("FINDER") == "FINDER":
        test_pass("osv_credit_type_to_tsa allowed")
    else:
        test_fail("osv_credit_type_to_tsa allowed", "Unexpected mapping")

    if oc._osv_credit_type_to_tsa("NONSTANDARD") == "OTHER":
        test_pass("osv_credit_type_to_tsa fallback")
    else:
        test_fail("osv_credit_type_to_tsa fallback", "Unexpected mapping")

    # resolve_tsa_id branches
    if oc._resolve_tsa_id("OSV-2025-0001", None, None).startswith("TSA-"):
        test_pass("resolve_tsa_id OSV prefix")
    else:
        test_fail("resolve_tsa_id OSV prefix", "Expected TSA prefix")

    if oc._resolve_tsa_id("TSA-OSV-2025-0001", None, None).startswith("TSA-"):
        test_pass("resolve_tsa_id TSA-OSV prefix")
    else:
        test_fail("resolve_tsa_id TSA-OSV prefix", "Expected TSA prefix")

    if oc._resolve_tsa_id("TSA-2025-0001", None, None) == "TSA-2025-0001":
        test_pass("resolve_tsa_id passthrough")
    else:
        test_fail("resolve_tsa_id passthrough", "Expected passthrough")

    if oc._resolve_tsa_id("GARBAGE", "TSA-2025-2222", None) == "TSA-2025-2222":
        test_pass("resolve_tsa_id explicit")
    else:
        test_fail("resolve_tsa_id explicit", "Expected explicit id")

    if oc._generate_tsa_id("GARBAGE", "invalid-date").startswith("TSA-TEST-"):
        test_pass("generate_tsa_id invalid published")
    else:
        test_fail("generate_tsa_id invalid published", "Expected TSA-TEST id")

    # CLI stdout branch and __main__
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        tmp.write(json.dumps(tsa_doc))
    argv_backup = list(sys.argv)
    try:
        sys.argv = ["osv_converter.py", "tsa-to-osv", tmp.name]
        try:
            runpy.run_path(str(resolve_tool_script("osv_converter.py")), run_name="__main__")
        except SystemExit:
            test_pass("osv_converter __main__")
    finally:
        sys.argv = argv_backup
        os.unlink(tmp.name)


def test_osv_converter_golden():
    """Golden output tests for TSA/OSV conversions."""
    log("\n=== OSV Converter Golden Tests ===")

    try:
        import tools.osv_converter as oc
    except ImportError as e:
        test_fail("OSV converter golden import", str(e))
        return

    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-0100",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "withdrawn": "2025-01-03T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Edge advisory",
        "description": "Detailed description",
        "severity": {
            "cvss_v4": {
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "score": 9.8,
            },
            "cvss_v3": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            },
        },
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm", "purl": "pkg:npm/demo@1.0.0"},
                "versions": {"introduced": "1.0.0", "fixed": "1.2.0"},
                "status": "AFFECTED",
                "capabilities_abused": ["filesystem.read"],
                "semantic_drift": {"original": "safe", "current": "unsafe", "impact": "HIGH"},
                "attack_context": {"requires_agent_execution": True},
                "impact_statement": "Impact",
            },
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"affected_range": ">=1.0.0 <1.1.0"},
                "status": "AFFECTED",
            },
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"affected_range": ">=1 <2"},
                "status": "AFFECTED",
            },
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"last_affected": "0.9.9"},
                "status": "AFFECTED",
            },
        ],
        "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
        "references": [
            {"type": "CVE", "id": "CVE-2025-0001", "url": "https://example.test/cve"},
            {"type": "WEB", "url": "https://example.test"},
        ],
        "related_vulnerabilities": [{"id": "CVE-2025-0002"}],
        "credits": [{"name": "Alice", "type": "FINDER", "contact": "alice@example.test"}],
    }

    expected_osv = {
        "schema_version": "1.6.0",
        "id": "TSA-OSV-2025-0100",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "withdrawn": "2025-01-03T00:00:00Z",
        "summary": "Edge advisory",
        "details": "Detailed description",
        "severity": [
            {
                "type": "CVSS_V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "score": "9.8",
            },
            {
                "type": "CVSS_V3",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": "9.8",
            },
        ],
        "affected": [
            {
                "package": {"name": "demo", "ecosystem": "npm", "purl": "pkg:npm/demo@1.0.0"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                    }
                ],
                "database_specific": {
                    "capabilities_abused": ["filesystem.read"],
                    "semantic_drift": {"original": "safe", "current": "unsafe", "impact": "HIGH"},
                    "attack_context": {"requires_agent_execution": True},
                    "impact_statement": "Impact",
                },
            },
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
            },
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"last_affected": "0.9.9"}],
                    }
                ],
            },
        ],
        "aliases": ["CVE-2025-0001", "CVE-2025-0002"],
        "references": [
            {"type": "ADVISORY", "url": "https://example.test/cve"},
            {"type": "WEB", "url": "https://example.test"},
        ],
        "credits": [
            {
                "name": "Alice",
                "type": "FINDER",
                "contact": ["alice@example.test"],
            }
        ],
        "database_specific": {"tsa_id": "TSA-2025-0100", "tsa_version": "1.0.0"},
    }

    osv_actual = oc.tsa_to_osv(tsa_doc)
    if osv_actual == expected_osv:
        test_pass("tsa_to_osv golden output")
    else:
        test_fail("tsa_to_osv golden output", "OSV output mismatch")

    osv_doc = {
        "schema_version": "1.6.0",
        "id": "GHSA-aaaa-bbbb-cccc",
        "published": "2025-02-01T00:00:00Z",
        "modified": "2025-02-02T00:00:00Z",
        "withdrawn": "2025-02-03T00:00:00Z",
        "summary": "OSV summary",
        "details": "OSV details",
        "severity": [
            {
                "type": "CVSS_V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "score": "9.8",
            },
            {
                "type": "CVSS_V3",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": "9.8",
            },
        ],
        "affected": [
            {
                "package": {
                    "name": "demo",
                    "ecosystem": "npm",
                    "purl": "pkg:npm/demo@2.0.0",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "2.0.0"},
                            {"fixed": "2.1.0"},
                            {"last_affected": "2.0.9"},
                        ],
                    }
                ],
                "database_specific": {
                    "capabilities_abused": ["filesystem.write"],
                    "semantic_drift": {"original": "safe", "current": "unsafe", "impact": "HIGH"},
                    "attack_context": {"requires_agent_execution": True},
                    "impact_statement": "Impact",
                },
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.test/advisory"},
            {"type": "ARTICLE", "url": "https://example.test/article"},
            {"type": "FIX", "url": "https://example.test/fix"},
            {"type": "REPORT", "url": "https://example.test/report"},
            {"type": "WEB", "url": "https://example.test/web"},
            {"type": "PACKAGE", "url": "https://example.test/pkg"},
            {"type": "EVIDENCE", "url": "https://example.test/evidence"},
            {"type": "DETECTION", "url": "https://example.test/detect"},
        ],
        "aliases": ["CVE-2025-9999"],
        "credits": [{"name": "Bob", "type": "FINDER", "contact": ["bob@example.test"]}],
    }

    expected_tsa = {
        "tsa_version": "1.0.0",
        "id": "TSA-TEST-2025-0241",
        "published": "2025-02-01T00:00:00Z",
        "modified": "2025-02-02T00:00:00Z",
        "withdrawn": "2025-02-03T00:00:00Z",
        "publisher": {"name": "OSV Import", "namespace": "https://osv.dev"},
        "title": "OSV summary",
        "description": "OSV details",
        "severity": {
            "cvss_v4": {
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                "score": 9.8,
            },
            "cvss_v3": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            },
        },
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm", "purl": "pkg:npm/demo@2.0.0"},
                "status": "AFFECTED",
                "versions": {"introduced": "2.0.0", "fixed": "2.1.0", "last_affected": "2.0.9"},
                "capabilities_abused": ["filesystem.write"],
                "semantic_drift": {"original": "safe", "current": "unsafe", "impact": "HIGH"},
                "attack_context": {"requires_agent_execution": True},
                "impact_statement": "Impact",
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.test/advisory"},
            {"type": "ARTICLE", "url": "https://example.test/article"},
            {"type": "FIX", "url": "https://example.test/fix"},
            {"type": "REPORT", "url": "https://example.test/report"},
            {"type": "WEB", "url": "https://example.test/web"},
            {"type": "WEB", "url": "https://example.test/pkg"},
            {"type": "OTHER", "url": "https://example.test/evidence"},
            {"type": "OTHER", "url": "https://example.test/detect"},
            {
                "type": "ADVISORY",
                "id": "GHSA-aaaa-bbbb-cccc",
                "url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
            },
            {
                "type": "CVE",
                "id": "CVE-2025-9999",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-9999",
            },
        ],
        "related_vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc"}],
        "actions": [
            {
                "type": "WARN",
                "urgency": "HIGH",
                "message": "Security vulnerability imported from OSV: GHSA-aaaa-bbbb-cccc",
            }
        ],
        "credits": [{"name": "Bob", "type": "FINDER", "contact": "bob@example.test"}],
    }

    tsa_actual = oc.osv_to_tsa(osv_doc)
    if tsa_actual == expected_tsa:
        test_pass("osv_to_tsa golden output")
    else:
        test_fail("osv_to_tsa golden output", "TSA output mismatch")


def test_osv_converter_mapping_tables():
    """Verify all OSV converter mapping tables."""
    log("\n=== OSV Converter Mapping Table Tests ===")

    try:
        import tools.osv_converter as oc
    except ImportError as e:
        test_fail("OSV converter mapping import", str(e))
        return

    registry_map = {
        "npm": "npm",
        "pypi": "PyPI",
        "crates": "crates.io",
        "maven": "Maven",
        "nuget": "NuGet",
        "go": "Go",
        "rubygems": "RubyGems",
    }
    for key, expected in registry_map.items():
        if oc._registry_to_ecosystem(key) == expected:
            test_pass(f"registry_to_ecosystem {key}")
        else:
            test_fail(f"registry_to_ecosystem {key}", "Unexpected mapping")

    ecosystem_map = {
        "npm": "npm",
        "pypi": "pypi",
        "crates.io": "crates",
        "maven": "maven",
        "nuget": "nuget",
        "go": "go",
        "rubygems": "rubygems",
    }
    for key, expected in ecosystem_map.items():
        if oc._ecosystem_to_registry(key) == expected:
            test_pass(f"ecosystem_to_registry {key}")
        else:
            test_fail(f"ecosystem_to_registry {key}", "Unexpected mapping")

    ref_map = {
        "CVE": "ADVISORY",
        "ADVISORY": "ADVISORY",
        "ARTICLE": "ARTICLE",
        "FIX": "FIX",
        "REPORT": "REPORT",
        "WEB": "WEB",
        "OTHER": "WEB",
    }
    for key, expected in ref_map.items():
        if oc._ref_type_to_osv(key) == expected:
            test_pass(f"ref_type_to_osv {key}")
        else:
            test_fail(f"ref_type_to_osv {key}", "Unexpected mapping")

    osv_ref_map = {
        "ADVISORY": "ADVISORY",
        "ARTICLE": "ARTICLE",
        "FIX": "FIX",
        "REPORT": "REPORT",
        "WEB": "WEB",
        "PACKAGE": "WEB",
        "EVIDENCE": "OTHER",
        "DETECTION": "OTHER",
    }
    for key, expected in osv_ref_map.items():
        if oc._osv_ref_type_to_tsa(key) == expected:
            test_pass(f"osv_ref_type_to_tsa {key}")
        else:
            test_fail(f"osv_ref_type_to_tsa {key}", "Unexpected mapping")

    credit_map = {
        "FINDER": "FINDER",
        "REPORTER": "REPORTER",
        "ANALYST": "ANALYST",
        "COORDINATOR": "COORDINATOR",
        "REMEDIATION_DEVELOPER": "REMEDIATION_DEVELOPER",
        "OTHER": "OTHER",
    }
    for key, expected in credit_map.items():
        if oc._credit_type_to_osv(key) == expected:
            test_pass(f"credit_type_to_osv {key}")
        else:
            test_fail(f"credit_type_to_osv {key}", "Unexpected mapping")

    allowed = {"FINDER", "REPORTER", "ANALYST", "COORDINATOR", "REMEDIATION_DEVELOPER"}
    for key in sorted(allowed):
        if oc._osv_credit_type_to_tsa(key) == key:
            test_pass(f"osv_credit_type_to_tsa {key}")
        else:
            test_fail(f"osv_credit_type_to_tsa {key}", "Unexpected mapping")


def test_build_feed_inline():
    """Test building an inline feed from local advisories."""
    log("\n=== Build Feed Tests ===")

    try:
        from tools.build_feed import build_feed
    except ImportError as e:
        test_fail("build_feed import", str(e))
        return

    advisory_dir = REPO_ROOT / "advisories"
    feed = build_feed(advisory_dir, inline=True)
    if feed.get("advisories") and all("canonical_hash" in a for a in feed["advisories"]):
        test_pass("build_feed inline advisories")
    else:
        test_fail("build_feed inline", "Missing advisories or canonical_hash")

    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from tools.tsactl_core import compute_canonical_hash
    except ImportError as e:
        test_fail("build_feed inline schema", f"jsonschema not installed: {e}")
        return

    schema_path = REPO_ROOT / "schema" / "tsa-feed-v1.0.0.schema.json"
    try:
        with open(schema_path) as f:
            schema = json.load(f)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = list(validator.iter_errors(feed))
        if errors:
            test_fail("build_feed inline schema", errors[0].message)
        else:
            test_pass("build_feed inline schema")
    except Exception as e:
        test_fail("build_feed inline schema", str(e))

    tsa_schema_path = REPO_ROOT / "schema" / "tsa-v1.0.0.schema.json"
    try:
        with open(tsa_schema_path) as f:
            tsa_schema = json.load(f)
        tsa_validator = Draft202012Validator(tsa_schema, format_checker=FormatChecker())
        for entry in feed.get("advisories", []):
            advisory = entry.get("advisory")
            if not advisory:
                test_fail("inline advisory validation", "Missing advisory payload")
                return
            errors = list(tsa_validator.iter_errors(advisory))
            if errors:
                test_fail("inline advisory validation", errors[0].message)
                return
            if entry.get("canonical_hash") != compute_canonical_hash(advisory):
                test_fail("inline advisory hash", "canonical_hash mismatch")
                return
        test_pass("inline advisory validation")
    except Exception as e:
        test_fail("inline advisory validation", str(e))


def test_build_feed_golden():
    """Golden output test for build_feed."""
    log("\n=== Build Feed Golden Tests ===")

    try:
        import tools.build_feed_core as bf
    except ImportError as e:
        test_fail("build_feed golden import", str(e))
        return

    fixed_time = datetime(2025, 1, 1, tzinfo=timezone.utc)

    class _FixedDateTime:
        @staticmethod
        def now(_tz=None):
            return fixed_time

    original_datetime = bf.datetime
    bf.datetime = _FixedDateTime
    try:
        feed = bf.build_feed(REPO_ROOT / "advisories", inline=False)
    finally:
        bf.datetime = original_datetime

    expected_path = REPO_ROOT / "feeds" / "sample-feed.json"
    with open(expected_path) as handle:
        expected = json.load(handle)
    expected["generated"] = "2025-01-01T00:00:00Z"

    if feed == expected:
        test_pass("build_feed golden output")
    else:
        test_fail("build_feed golden output", "Feed output mismatch")


def test_build_feed_fallback():
    """Exercise build_feed fallback canonicalization and CLI branches."""
    log("\n=== Build Feed Fallback Tests ===")

    module = load_module_from_path(
        "build_feed_fallback",
        TOOLS_ROOT / "tools" / "build_feed_core.py",
        blocked_imports=["tools.tsactl", "tsactl"],
    )

    # Fallback canonicalize branches
    if module.canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}':
        test_pass("build_feed fallback canonicalize dict")
    else:
        test_fail("build_feed fallback canonicalize dict", "Unexpected output")

    if module.canonicalize([1, True]) == "[1,true]":
        test_pass("build_feed fallback canonicalize list")
    else:
        test_fail("build_feed fallback canonicalize list", "Unexpected output")

    if module.canonicalize("test") == '"test"':
        test_pass("build_feed fallback canonicalize string")
    else:
        test_fail("build_feed fallback canonicalize string", "Unexpected output")

    if module.canonicalize(None) == "null":
        test_pass("build_feed fallback canonicalize null")
    else:
        test_fail("build_feed fallback canonicalize null", "Unexpected output")

    if module.canonicalize(1.0) == "1":
        test_pass("build_feed fallback canonicalize float")
    else:
        test_fail("build_feed fallback canonicalize float", "Unexpected output")

    original_repr = getattr(module, "repr", None)
    module.repr = lambda _value: "1.0"
    try:
        if module.canonicalize(1.5) == "1.0":
            test_pass("build_feed fallback float trim")
        else:
            test_fail("build_feed fallback float trim", "Unexpected output")
    finally:
        if original_repr is None:
            delattr(module, "repr")
        else:
            module.repr = original_repr

    try:
        module.canonicalize(float("nan"))
        test_fail("build_feed fallback NaN", "Expected ValueError")
    except ValueError:
        test_pass("build_feed fallback NaN")

    try:
        module.canonicalize(float("inf"))
        test_fail("build_feed fallback inf", "Expected ValueError")
    except ValueError:
        test_pass("build_feed fallback inf")

    try:
        module.canonicalize({1, 2})
        test_fail("build_feed fallback unsupported", "Expected TypeError")
    except TypeError:
        test_pass("build_feed fallback unsupported")

    if module.compute_canonical_hash({"a": 1}).startswith("sha256:"):
        test_pass("build_feed fallback canonical hash")
    else:
        test_fail("build_feed fallback canonical hash", "Missing sha256 prefix")

    # main() with stdout branch
    import tools.build_feed as build_feed_cli

    argv_backup = list(sys.argv)
    try:
        sys.argv = ["build_feed.py", str(REPO_ROOT / "advisories"), "--pretty"]
        if build_feed_cli.main() == 0:
            test_pass("build_feed main stdout")
        else:
            test_fail("build_feed main stdout", "Non-zero exit")
    finally:
        sys.argv = argv_backup

    # __main__ error branch
    argv_backup = list(sys.argv)
    try:
        sys.argv = ["build_feed.py", "missing-dir"]
        try:
            runpy.run_path(str(resolve_tool_script("build_feed.py")), run_name="__main__")
        except SystemExit:
            test_pass("build_feed __main__ error")
    finally:
        sys.argv = argv_backup


def test_build_feed_variants():
    """Test build_feed options (base_url, ordering, and error handling)."""
    log("\n=== Build Feed Variant Tests ===")

    try:
        from tools.build_feed import build_feed
    except ImportError as e:
        test_fail("build_feed import", str(e))
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        advisory_dir = tmp_path / "advisories"
        advisory_dir.mkdir()

        adv1 = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-2025-0001",
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-01T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "title": "Older advisory",
            "affected": [{"tool": {"name": "demo", "registry": "npm"}, "status": "AFFECTED"}],
            "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
        }
        adv2 = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-2025-0002",
            "published": "2025-01-02T00:00:00Z",
            "modified": "2025-01-02T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "title": "Newer advisory",
            "affected": [{"tool": {"name": "demo", "registry": "npm"}, "status": "AFFECTED"}],
            "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
        }

        adv3 = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-2025-0003",
            "published": "2025-01-03T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "title": "Missing modified",
            "affected": [{"tool": {"name": "demo", "registry": "npm"}, "status": "AFFECTED"}],
            "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
        }

        (advisory_dir / "a1.tsa.json").write_text(json.dumps(adv1))
        (advisory_dir / "a2.tsa.json").write_text(json.dumps(adv2))
        (advisory_dir / "a3.tsa.json").write_text(json.dumps(adv3))
        (advisory_dir / "invalid.tsa.json").write_text("{invalid-json")

        with contextlib.redirect_stderr(io.StringIO()):
            feed = build_feed(advisory_dir, base_url="https://example.test/advisories/")
        if feed.get("advisories") and feed["advisories"][0].get("id") == "TSA-TEST-2025-0002":
            test_pass("build_feed orders by modified desc")
        else:
            test_fail("build_feed ordering", "Expected newest advisory first")

        advisory_ids = [entry.get("id") for entry in feed.get("advisories", [])]
        if advisory_ids and advisory_ids[-1] == "TSA-TEST-2025-0003":
            test_pass("build_feed missing modified sorts last")
        else:
            test_fail("build_feed missing modified sorts last", f"Order: {advisory_ids}")

        if all(
            entry.get("uri", "").startswith("https://example.test/advisories/")
            for entry in feed.get("advisories", [])
        ):
            test_pass("build_feed base_url")
        else:
            test_fail("build_feed base_url", "URIs missing base_url")

        if all("advisory" not in entry for entry in feed.get("advisories", [])):
            test_pass("build_feed non-inline entries")
        else:
            test_fail("build_feed non-inline entries", "Unexpected advisory payload")

        feed_x = build_feed(advisory_dir, base_url="https://example.test/baseX")
        if all(
            entry.get("uri", "").startswith("https://example.test/baseX/")
            for entry in feed_x.get("advisories", [])
        ):
            test_pass("build_feed base_url preserves trailing X")
        else:
            test_fail("build_feed base_url preserves trailing X", "Unexpected base_url trimming")


# =============================================================================
# CLI E2E Tests
# =============================================================================


def test_cli_e2e():
    """End-to-end CLI tests for tsactl, build_feed, and osv_converter."""
    log("\n=== CLI E2E Tests ===")

    if MUTANTS_ROOT is not None:
        test_pass("CLI E2E (skipped under mutmut)")
        return

    python = sys.executable
    tsactl = "tools.tsactl"
    build_feed = "tools.build_feed"
    osv_converter = "tools.osv_converter"

    advisory = REPO_ROOT / "advisories" / "TSA-2025-0001-mcp-remote-rce.tsa.json"
    inventory = REPO_ROOT / "test-vectors" / "sample-inventory.json"
    minimal = REPO_ROOT / "test-vectors" / "tv01-minimal.tsa.json"

    result = subprocess.run(
        [python, "-m", tsactl, "validate", str(advisory)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    if result.returncode == 0:
        test_pass("tsactl validate (valid)")
    else:
        test_fail("tsactl validate (valid)", result.stderr.strip() or result.stdout.strip())

    with tempfile.TemporaryDirectory() as tmpdir:
        invalid_path = Path(tmpdir) / "invalid.json"
        invalid_path.write_text("{}")
        result = subprocess.run(
            [python, "-m", tsactl, "validate", str(invalid_path)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            test_pass("tsactl validate (invalid)")
        else:
            test_fail("tsactl validate (invalid)", "Expected non-zero exit code")

        result = subprocess.run(
            [python, "-m", tsactl, "match", str(advisory), str(inventory)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode == 2:
            test_pass("tsactl match (affected inventory)")
        else:
            test_fail("tsactl match", f"Expected exit code 2, got {result.returncode}")

        key_prefix = Path(tmpdir) / "testkey"
        result = subprocess.run(
            [python, "-m", tsactl, "generate-keys", str(key_prefix)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        private_key = Path(f"{key_prefix}_private.pem")
        public_key = Path(f"{key_prefix}_public.pem")
        if result.returncode == 0 and private_key.exists() and public_key.exists():
            test_pass("tsactl generate-keys")
        else:
            test_fail("tsactl generate-keys", result.stderr.strip() or result.stdout.strip())
            return

        signed_path = Path(tmpdir) / "signed.json"
        result = subprocess.run(
            [
                python,
                "-m",
                tsactl,
                "sign",
                str(minimal),
                str(private_key),
                "--key-id",
                "test:key1",
                "--output",
                str(signed_path),
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode == 0 and signed_path.exists():
            test_pass("tsactl sign")
        else:
            test_fail("tsactl sign", result.stderr.strip() or result.stdout.strip())
            return

        result = subprocess.run(
            [python, "-m", tsactl, "verify", str(signed_path), str(public_key)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode == 0:
            test_pass("tsactl verify")
        else:
            test_fail("tsactl verify", result.stderr.strip() or result.stdout.strip())

        feed_path = Path(tmpdir) / "feed.json"
        result = subprocess.run(
            [
                python,
                "-m",
                build_feed,
                "advisories",
                "--inline",
                "--output",
                str(feed_path),
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode == 0 and feed_path.exists():
            try:
                with open(feed_path) as f:
                    feed = json.load(f)
                if feed.get("advisories"):
                    test_pass("build_feed CLI")
                else:
                    test_fail("build_feed CLI", "No advisories in feed")
            except Exception as e:
                test_fail("build_feed CLI", str(e))
        else:
            test_fail("build_feed CLI", result.stderr.strip() or result.stdout.strip())

        osv_path = Path(tmpdir) / "out.osv.json"
        result = subprocess.run(
            [
                python,
                "-m",
                osv_converter,
                "tsa-to-osv",
                str(advisory),
                "--output",
                str(osv_path),
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode == 0 and osv_path.exists():
            test_pass("osv_converter CLI")
        else:
            test_fail("osv_converter CLI", result.stderr.strip() or result.stdout.strip())

        osv_input = Path(tmpdir) / "in.osv.json"
        osv_input.write_text(
            json.dumps(
                {
                    "id": "GHSA-0000-0000-0000",
                    "summary": "OSV import test",
                    "published": "2025-01-01T00:00:00Z",
                }
            )
        )
        tsa_out = Path(tmpdir) / "out.tsa.json"
        result = subprocess.run(
            [
                python,
                "-m",
                osv_converter,
                "osv-to-tsa",
                str(osv_input),
                "--output",
                str(tsa_out),
                "--id",
                "TSA-2025-9001",
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if result.returncode == 0 and tsa_out.exists():
            try:
                with open(tsa_out) as f:
                    tsa_doc = json.load(f)
                if tsa_doc.get("id") == "TSA-2025-9001":
                    test_pass("osv_converter CLI osv-to-tsa")
                else:
                    test_fail("osv_converter CLI osv-to-tsa", "Unexpected TSA id")
            except Exception as e:
                test_fail("osv_converter CLI osv-to-tsa", str(e))
        else:
            test_fail(
                "osv_converter CLI osv-to-tsa",
                result.stderr.strip() or result.stdout.strip(),
            )


# =============================================================================
# CLI Entrypoint (In-Process) Tests
# =============================================================================


def test_cli_entrypoints_in_process():
    """Exercise CLI entrypoints in-process for mutation coverage."""
    log("\n=== CLI Entrypoint Tests ===")

    try:
        import tools.build_feed as build_feed
        import tools.osv_converter as osv_converter
        import tools.tsa_registry_sdk as tsa_registry_sdk
        import tools.tsactl as tsactl
    except ImportError as e:
        test_fail("CLI entrypoints import", str(e))
        return

    advisory = REPO_ROOT / "advisories" / "TSA-2025-0001-mcp-remote-rce.tsa.json"
    inventory = REPO_ROOT / "test-vectors" / "sample-inventory.json"
    minimal = REPO_ROOT / "test-vectors" / "tv01-minimal.tsa.json"

    argv_backup = list(sys.argv)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            key_prefix = Path(tmpdir) / "cli"
            private_key = Path(f"{key_prefix}_private.pem")
            public_key = Path(f"{key_prefix}_public.pem")
            signed_path = Path(tmpdir) / "signed.json"

            sys.argv = ["tsactl", "validate", str(advisory)]
            test_pass("tsactl main validate") if tsactl.main() == 0 else test_fail(
                "tsactl main validate", "Non-zero exit"
            )

            sys.argv = ["tsactl", "canonicalize", str(minimal)]
            test_pass("tsactl main canonicalize") if tsactl.main() == 0 else test_fail(
                "tsactl main canonicalize", "Non-zero exit"
            )

            sys.argv = ["tsactl", "hash", str(minimal)]
            test_pass("tsactl main hash") if tsactl.main() == 0 else test_fail(
                "tsactl main hash", "Non-zero exit"
            )

            sys.argv = ["tsactl", "match", str(advisory), str(inventory)]
            test_pass("tsactl main match") if tsactl.main() == 2 else test_fail(
                "tsactl main match", "Expected exit code 2"
            )

            sys.argv = ["tsactl", "generate-keys", str(key_prefix)]
            test_pass("tsactl main generate-keys") if tsactl.main() == 0 else test_fail(
                "tsactl main generate-keys", "Non-zero exit"
            )

            sys.argv = [
                "tsactl",
                "sign",
                str(minimal),
                str(private_key),
                "--key-id",
                "test:key1",
                "--output",
                str(signed_path),
            ]
            test_pass("tsactl main sign") if tsactl.main() == 0 else test_fail(
                "tsactl main sign", "Non-zero exit"
            )

            sys.argv = ["tsactl", "verify", str(signed_path), str(public_key)]
            test_pass("tsactl main verify") if tsactl.main() == 0 else test_fail(
                "tsactl main verify", "Non-zero exit"
            )

            feed_path = Path(tmpdir) / "feed.json"
            sys.argv = [
                "build_feed.py",
                "advisories",
                "--inline",
                "--output",
                str(feed_path),
            ]
            test_pass("build_feed main") if build_feed.main() == 0 else test_fail(
                "build_feed main", "Non-zero exit"
            )

            osv_path = Path(tmpdir) / "out.osv.json"
            sys.argv = [
                "osv_converter.py",
                "tsa-to-osv",
                str(advisory),
                "--output",
                str(osv_path),
            ]
            test_pass("osv_converter main") if osv_converter.main() == 0 else test_fail(
                "osv_converter main", "Non-zero exit"
            )

            osv_input = Path(tmpdir) / "in.osv.json"
            osv_input.write_text(
                json.dumps(
                    {
                        "id": "GHSA-1111-2222-3333",
                        "summary": "OSV in-process test",
                        "published": "2025-01-01T00:00:00Z",
                    }
                )
            )
            tsa_out = Path(tmpdir) / "out.tsa.json"
            sys.argv = [
                "osv_converter.py",
                "osv-to-tsa",
                str(osv_input),
                "--output",
                str(tsa_out),
                "--id",
                "TSA-2025-9002",
            ]
            test_pass("osv_converter main osv-to-tsa") if osv_converter.main() == 0 else test_fail(
                "osv_converter main osv-to-tsa", "Non-zero exit"
            )
    finally:
        sys.argv = argv_backup

    try:
        tsa_registry_sdk.demo()
        test_pass("tsa_registry_sdk demo")
    except Exception as e:
        test_fail("tsa_registry_sdk demo", str(e))


# =============================================================================
# SDK Tests
# =============================================================================


def test_registry_sdk():
    """Test the TSA Registry SDK."""
    log("\n=== Registry SDK Tests ===")

    try:
        from tools.tsa_registry_sdk import TSARegistry
    except ImportError:
        test_fail("SDK import", "Could not import tsa_registry_sdk")
        return

    # Create registry
    try:
        registry = TSARegistry()
        test_pass("SDK instantiation")
    except Exception as e:
        test_fail("SDK instantiation", str(e))
        return

    # Add sample advisory
    sample_advisory = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-0001",
        "published": "2025-07-09T00:00:00Z",
        "modified": "2025-07-09T18:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://test.example"},
        "title": "Test Advisory for SDK",
        "affected": [
            {
                "tool": {"name": "mcp-remote", "registry": "npm"},
                "versions": {
                    "introduced": "0.0.5",
                    "fixed": "0.1.16",
                    "affected_range": ">=0.0.5 <0.1.16",
                },
                "status": "AFFECTED",
            }
        ],
        "actions": [
            {
                "type": "BLOCK",
                "condition": ">=0.0.5 <0.1.16",
                "urgency": "IMMEDIATE",
                "message": "Test block message",
            }
        ],
    }

    try:
        registry.add_advisory(sample_advisory)
        test_pass("SDK add_advisory")
    except Exception as e:
        test_fail("SDK add_advisory", str(e))
        return

    # Test vulnerable version blocked
    try:
        result = registry.check_package("mcp-remote", "0.1.14", "npm")
        if result.blocked:
            test_pass("SDK blocks vulnerable version")
        else:
            test_fail("SDK vulnerable blocking", "Should have blocked 0.1.14")
    except Exception as e:
        test_fail("SDK check vulnerable", str(e))

    # Test fixed version not blocked
    try:
        result = registry.check_package("mcp-remote", "0.1.16", "npm")
        if not result.blocked:
            test_pass("SDK allows fixed version")
        else:
            test_fail("SDK fixed version", "Should not block 0.1.16")
    except Exception as e:
        test_fail("SDK check fixed", str(e))

    # Test unaffected package
    try:
        result = registry.check_package("other-package", "1.0.0", "npm")
        if not result.blocked and len(result.advisories) == 0:
            test_pass("SDK ignores unaffected package")
        else:
            test_fail("SDK unaffected", "Should have no advisories for other-package")
    except Exception as e:
        test_fail("SDK check unaffected", str(e))


def test_registry_feed_sync():
    """Test registry feed sync, URL resolution, and hash validation."""
    log("\n=== Registry Feed Sync Tests ===")

    try:
        from tools.tsa_registry_sdk import TSARegistry
        from tools.tsactl_core import compute_canonical_hash
    except ImportError as e:
        test_fail("Registry feed imports", str(e))
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        advisory = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-2025-0100",
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-01T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "title": "Feed sync test",
            "affected": [{"tool": {"name": "demo", "registry": "npm"}, "status": "AFFECTED"}],
            "actions": [{"type": "WARN", "urgency": "LOW", "message": "Test"}],
        }
        advisory_path = tmp_path / "advisory.tsa.json"
        advisory_path.write_text(json.dumps(advisory))
        canonical_hash = compute_canonical_hash(advisory)

        feed = {
            "feed_version": "1.0.0",
            "generated": "2025-01-01T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "advisories": [
                {
                    "id": advisory["id"],
                    "uri": "advisory.tsa.json",
                    "canonical_hash": canonical_hash,
                }
            ],
        }
        feed_path = tmp_path / "feed.json"
        feed_path.write_text(json.dumps(feed))

        registry = TSARegistry()
        registry.subscribe_feed(f"file://{feed_path}")
        stats = registry.sync()
        if stats.get("advisories_added") == 1 and registry.get_advisory(advisory["id"]):
            test_pass("Registry sync file:// feed")
        else:
            test_fail("Registry sync file:// feed", f"Stats: {stats}")

        if registry.last_sync and registry.last_sync.tzinfo is not None:
            test_pass("Registry sync timestamp tz-aware")
        else:
            test_fail("Registry sync timestamp tz-aware", f"last_sync={registry.last_sync}")

        bad_feed = {
            **feed,
            "advisories": [
                {
                    "id": advisory["id"],
                    "uri": "advisory.tsa.json",
                    "canonical_hash": "sha256:" + "0" * 64,
                }
            ],
        }
        bad_feed_path = tmp_path / "bad-feed.json"
        bad_feed_path.write_text(json.dumps(bad_feed))

        registry_bad = TSARegistry()
        registry_bad.subscribe_feed(str(bad_feed_path))
        with contextlib.redirect_stderr(io.StringIO()):
            bad_stats = registry_bad.sync()
        if bad_stats.get("advisories_added") == 0:
            test_pass("Registry hash mismatch skip")
        else:
            test_fail("Registry hash mismatch skip", f"Stats: {bad_stats}")

        # Sync error message handling
        registry_err = TSARegistry()
        registry_err.feeds = ["good", "bad"]

        def fake_sync(url):
            if url == "bad":
                raise RuntimeError("boom")
            return {"added": 0, "updated": 0}

        registry_err._sync_feed = fake_sync
        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            err_stats = registry_err.sync()
        err_msg = err_stats.get("errors", [None])[0]
        if (
            err_msg
            and "Failed to sync bad: boom" in err_msg
            and "Failed to sync bad: boom" in stderr_buf.getvalue()
        ):
            test_pass("Registry sync error message")
        else:
            test_fail("Registry sync error message", f"Unexpected error output: {err_msg}")


def test_registry_feed_sync_edge_cases():
    """Exercise sync edge cases for warnings, counts, and URL handling."""
    log("\n=== Registry Feed Sync Edge Tests ===")

    try:
        from tools.tsa_registry_sdk import TSARegistry
        from tools.tsactl_core import compute_canonical_hash
    except ImportError as e:
        test_fail("Registry sync edge imports", str(e))
        return

    advisory = {
        "id": "TSA-EDGE-1",
        "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
    }

    # Hash mismatch should include advisory id in warning
    registry = TSARegistry()
    feed_data = {
        "advisories": [{"id": "TSA-EDGE-1", "advisory": advisory, "canonical_hash": "sha256:bad"}]
    }
    registry._fetch_url = lambda _url: feed_data
    stderr_buf = io.StringIO()
    with contextlib.redirect_stderr(stderr_buf):
        registry._sync_feed("feed")
    if "Hash mismatch for TSA-EDGE-1" in stderr_buf.getvalue():
        test_pass("Registry hash mismatch warns with id")
    else:
        test_fail("Registry hash mismatch warns with id", stderr_buf.getvalue())

    # Continue when advisory missing
    registry_missing = TSARegistry()
    good_adv = {"id": "TSA-GOOD", "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}]}
    feed_missing = {"advisories": [{"id": "TSA-NONE"}, {"id": "TSA-GOOD", "advisory": good_adv}]}
    registry_missing._fetch_url = lambda _url: feed_missing
    stats_missing = registry_missing._sync_feed("feed")
    if stats_missing.get("added") == 1 and registry_missing.get_advisory("TSA-GOOD"):
        test_pass("Registry continues after missing advisory")
    else:
        test_fail("Registry continues after missing advisory", f"Stats: {stats_missing}")

    # Continue after hash mismatch
    registry_hash = TSARegistry()
    good_hash = compute_canonical_hash(good_adv)
    feed_hash = {
        "advisories": [
            {"id": "TSA-BAD", "advisory": advisory, "canonical_hash": "sha256:bad"},
            {"id": "TSA-GOOD", "advisory": good_adv, "canonical_hash": good_hash},
        ]
    }
    registry_hash._fetch_url = lambda _url: feed_hash
    stats_hash = registry_hash._sync_feed("feed")
    if stats_hash.get("added") == 1 and registry_hash.get_advisory("TSA-GOOD"):
        test_pass("Registry continues after hash mismatch")
    else:
        test_fail("Registry continues after hash mismatch", f"Stats: {stats_hash}")

    # Added count accumulates for multiple entries
    registry_added = TSARegistry()
    adv_a = {"id": "TSA-A", "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}]}
    adv_b = {"id": "TSA-B", "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}]}
    feed_multi = {
        "advisories": [{"id": "TSA-A", "advisory": adv_a}, {"id": "TSA-B", "advisory": adv_b}]
    }
    registry_added._fetch_url = lambda _url: feed_multi
    stats_added = registry_added._sync_feed("feed")
    if stats_added.get("added") == 2:
        test_pass("Registry added count accumulates")
    else:
        test_fail("Registry added count accumulates", f"Stats: {stats_added}")

    # Updated count accumulates for multiple entries
    registry_updated = TSARegistry()
    registry_updated.advisories = {"TSA-A": adv_a, "TSA-B": adv_b}
    registry_updated._fetch_url = lambda _url: feed_multi
    stats_updated = registry_updated._sync_feed("feed")
    if stats_updated.get("updated") == 2:
        test_pass("Registry updated count accumulates")
    else:
        test_fail("Registry updated count accumulates", f"Stats: {stats_updated}")

    # Absolute URL handling should not resolve relative paths
    for label, adv_url in [
        ("http", "http://example.test/adv.json"),
        ("https", "https://example.test/adv.json"),
        ("file", "file:///tmp/adv.json"),
    ]:
        registry_abs = TSARegistry()
        called = {"value": False}

        def fake_resolve(_base, _rel):
            called["value"] = True
            return "resolved"

        registry_abs._resolve_url = fake_resolve

        feed_abs = {"advisories": [{"id": f"TSA-{label}", "url": adv_url}]}

        def fake_fetch(url):
            if url == "feed":
                return feed_abs
            return {
                "id": f"TSA-{label}",
                "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
            }

        registry_abs._fetch_url = fake_fetch
        stats_abs = registry_abs._sync_feed("feed")
        if not called["value"] and stats_abs.get("added") == 1:
            test_pass(f"Registry absolute URL {label}")
        else:
            test_fail(f"Registry absolute URL {label}", "Unexpected resolve_url call")

    # Entry processing errors should include id or unknown in stderr
    registry_err = TSARegistry()
    feed_err = {
        "advisories": [
            {"id": "TSA-ERR-ID", "url": "bad1.json"},
            {"url": "bad2.json"},
        ]
    }

    def err_fetch(url):
        if url == "feed":
            return feed_err
        raise RuntimeError("boom")

    registry_err._fetch_url = err_fetch
    stderr_buf = io.StringIO()
    with contextlib.redirect_stderr(stderr_buf):
        registry_err._sync_feed("feed")
    stderr_val = stderr_buf.getvalue()
    if (
        "Failed to process entry TSA-ERR-ID" in stderr_val
        and "Failed to process entry unknown" in stderr_val
    ):
        test_pass("Registry entry error message includes id")
    else:
        test_fail("Registry entry error message includes id", stderr_val)


def test_registry_signature_policy():
    """Test signature enforcement and trust anchor loading."""
    log("\n=== Registry Signature Policy Tests ===")

    try:
        from tools.tsa_registry_sdk import TSARegistry
    except ImportError as e:
        test_fail("Registry signature imports", str(e))
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        anchors_path = Path(tmpdir) / "trust-anchors.json"
        anchors_path.write_text(
            json.dumps(
                {
                    "anchors": [
                        {
                            "key_id": "test:key1",
                            "public_key": "test",
                            "publisher": "Test Publisher",
                            "trust_level": "full",
                        }
                    ]
                }
            )
        )
        registry = TSARegistry(trust_anchors_path=str(anchors_path), require_signatures=True)
        if registry.trust_anchors:
            test_pass("Registry loads trust anchors")
        else:
            test_fail("Registry loads trust anchors", "No anchors loaded")

        advisory = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-2025-0101",
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-01T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "title": "Unsigned block test",
            "affected": [
                {
                    "tool": {"name": "demo", "registry": "npm"},
                    "versions": {"affected_range": ">=0.0.1 <1.0.0"},
                    "status": "AFFECTED",
                }
            ],
            "actions": [
                {
                    "type": "BLOCK",
                    "condition": ">=0.0.1 <1.0.0",
                    "urgency": "IMMEDIATE",
                    "message": "Test block",
                }
            ],
        }
        with contextlib.redirect_stderr(io.StringIO()):
            registry.add_advisory(advisory)
            result = registry.check_package("demo", "0.5.0", "npm")
            if not result.blocked and result.warnings:
                test_pass("Registry unsigned BLOCK downgraded to WARN")
            else:
                test_fail("Registry unsigned BLOCK downgraded", "Expected WARN-only behavior")


def test_registry_action_handling():
    """Exercise action conditions and blocking behavior."""
    log("\n=== Registry Action Handling Tests ===")

    try:
        from tools.tsa_registry_sdk import TSARegistry, TrustAnchor
        from tools import tsactl_core
    except ImportError as e:
        test_fail("Registry action imports", str(e))
        return

    registry = TSARegistry(require_signatures=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path, pub_path = tsactl_core.generate_keys(os.path.join(tmpdir, "registry"))
        with open(pub_path, "r") as f:
            pub_pem = f.read()

        registry.trust_anchors["trusted:key1"] = TrustAnchor(
            key_id="trusted:key1", public_key=pub_pem, publisher="Test Publisher"
        )

        advisory = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-2025-0200",
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-02T00:00:00Z",
            "publisher": {"name": "Test", "namespace": "https://example.test"},
            "title": "Action test",
            "affected": [
                {
                    "tool": {"name": "demo", "registry": "npm"},
                    "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
                    "status": "AFFECTED",
                }
            ],
            "actions": [
                {
                    "type": "BLOCK",
                    "condition": ">=1.0.0 <2.0.0",
                    "urgency": "IMMEDIATE",
                    "message": "Block demo",
                },
                {
                    "type": "WARN",
                    "condition": ">=1.5.0 <2.0.0",
                    "urgency": "LOW",
                    "message": "Warn demo",
                },
                {
                    "type": "WARN",
                    "condition": ">=3.0.0",
                    "urgency": "LOW",
                    "message": "Out of range",
                },
            ],
        }

        signed_advisory = tsactl_core.sign_document(advisory, priv_path, "trusted:key1")
        registry.add_advisory(signed_advisory)

        result = registry.check_package("demo", "1.6.0", "npm")
        if result.blocked and result.message == "Block demo":
            test_pass("Registry blocks matching version")
        else:
            test_fail("Registry blocks matching version", f"Result: {result.to_dict()}")

        if "Warn demo" in result.warnings and "Out of range" not in result.warnings:
            test_pass("Registry warns on matching condition only")
        else:
            test_fail("Registry warns on matching condition only", f"Warnings: {result.warnings}")

        if len(result.actions) == 2:
            test_pass("Registry actions filtered by condition")
        else:
            test_fail("Registry actions filtered by condition", f"Actions: {result.actions}")

        result_fixed = registry.check_package("demo", "2.0.0", "npm")
        if not result_fixed.advisories and not result_fixed.blocked:
            test_pass("Registry ignores fixed version")
        else:
            test_fail("Registry ignores fixed version", f"Result: {result_fixed.to_dict()}")

    # Operator coverage for _matches_range and _matches_condition
    if registry._matches_range("1.2.3", ">=1.2.0") and not registry._matches_range(
        "1.2.3", ">1.2.3"
    ):
        test_pass("Registry range operators >=")
    else:
        test_fail("Registry range operators >=", "Unexpected range result")

    if registry._matches_range("1.2.3", "<=1.2.3") and not registry._matches_range(
        "1.2.3", "<1.2.3"
    ):
        test_pass("Registry range operators <=")
    else:
        test_fail("Registry range operators <=", "Unexpected range result")

    if registry._matches_range("1.2.3", "=1.2.3") and not registry._matches_range(
        "1.2.3", "=1.2.4"
    ):
        test_pass("Registry range operators =")
    else:
        test_fail("Registry range operators =", "Unexpected range result")

    if registry._matches_condition("1.2.3", ">=1.0.0 and <2.0.0"):
        test_pass("Registry matches_condition normalization")
    else:
        test_fail("Registry matches_condition normalization", "Expected condition match")

    if registry._matches_range("1.0.0", ">=1.0.0,<=2.0.0"):
        test_pass("Registry matches_range commas")
    else:
        test_fail("Registry matches_range commas", "Expected comma range match")

    if registry._matches_condition("1.0.0", ">=1.0.0,<=2.0.0"):
        test_pass("Registry matches_condition commas")
    else:
        test_fail("Registry matches_condition commas", "Expected comma condition match")


def test_registry_sdk_edge_cases():
    """Exercise remaining registry SDK branches for coverage."""
    log("\n=== Registry SDK Edge Tests ===")

    module = load_module_from_path(
        "tsa_registry_sdk_fallback",
        TOOLS_ROOT / "tools" / "tsa_registry_sdk_core.py",
        blocked_imports=["tools.tsactl", "tsactl"],
    )
    crypto_blocked = load_module_from_path(
        "tsa_registry_sdk_no_crypto",
        TOOLS_ROOT / "tools" / "tsa_registry_sdk_core.py",
        blocked_imports=["tools.tsactl", "tsactl", "cryptography"],
    )
    if crypto_blocked.CRYPTO_AVAILABLE is False:
        test_pass("registry crypto import fallback")
    else:
        test_fail("registry crypto import fallback", "Expected CRYPTO_AVAILABLE False")

    if module.canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}':
        test_pass("registry fallback canonicalize")
    else:
        test_fail("registry fallback canonicalize", "Unexpected output")

    if module.compute_canonical_hash({"a": 1}).startswith("sha256:"):
        test_pass("registry fallback hash")
    else:
        test_fail("registry fallback hash", "Missing sha256 prefix")

    if module.canonicalize(None) == "null":
        test_pass("registry fallback null")
    else:
        test_fail("registry fallback null", "Unexpected output")

    if module.canonicalize(True) == "true":
        test_pass("registry fallback bool")
    else:
        test_fail("registry fallback bool", "Unexpected output")

    if module.canonicalize([1, False]) == "[1,false]":
        test_pass("registry fallback list")
    else:
        test_fail("registry fallback list", "Unexpected output")

    if module.canonicalize("x") == '"x"':
        test_pass("registry fallback string")
    else:
        test_fail("registry fallback string", "Unexpected output")

    if module.canonicalize(1.0) == "1":
        test_pass("registry fallback integral float")
    else:
        test_fail("registry fallback integral float", "Unexpected output")

    original_repr = getattr(module, "repr", None)
    module.repr = lambda _value: "1.0"
    try:
        if module.canonicalize(1.5) == "1.0":
            test_pass("registry fallback float trim")
        else:
            test_fail("registry fallback float trim", "Unexpected output")
    finally:
        if original_repr is None:
            delattr(module, "repr")
        else:
            module.repr = original_repr

    for label, value in [("nan", float("nan")), ("inf", float("inf"))]:
        try:
            module.canonicalize(value)
            test_fail(f"registry fallback {label}", "Expected ValueError")
        except ValueError:
            test_pass(f"registry fallback {label}")

    try:
        module.canonicalize({1, 2})
        test_fail("registry fallback type error", "Expected TypeError")
    except TypeError:
        test_pass("registry fallback type error")

    if module._parse_semver("not-a-version") is None:
        test_pass("registry parse_semver invalid")
    else:
        test_fail("registry parse_semver invalid", "Expected None")

    if module._compare_prerelease([(True, 1)], [(True, 2)]) < 0:
        test_pass("registry prerelease numeric <")
    else:
        test_fail("registry prerelease numeric <", "Expected 1 < 2")

    if module._compare_prerelease([(True, 2)], [(True, 1)]) == 1:
        test_pass("registry prerelease numeric >")
    else:
        test_fail("registry prerelease numeric >", "Expected 2 > 1")

    if module._compare_prerelease([(True, 1)], [(False, "a")]) < 0:
        test_pass("registry prerelease numeric < string")
    else:
        test_fail("registry prerelease numeric < string", "Expected numeric < string")

    if module._compare_prerelease([(False, "a")], [(True, 1)]) > 0:
        test_pass("registry prerelease string > numeric")
    else:
        test_fail("registry prerelease string > numeric", "Expected string > numeric")

    if module._compare_prerelease([(False, "a")], [(False, "b")]) < 0:
        test_pass("registry prerelease lexicographic <")
    else:
        test_fail("registry prerelease lexicographic <", "Expected a < b")

    if module._compare_prerelease([(False, "b")], [(False, "a")]) == 1:
        test_pass("registry prerelease lexicographic >")
    else:
        test_fail("registry prerelease lexicographic >", "Expected exact return of 1")

    if module._compare_prerelease([(True, 1)], [(True, 1), (True, 2)]) < 0:
        test_pass("registry prerelease length <")
    else:
        test_fail("registry prerelease length <", "Expected shorter < longer")

    if module._compare_prerelease([(True, 1), (True, 2)], [(True, 1)]) > 0:
        test_pass("registry prerelease length >")
    else:
        test_fail("registry prerelease length >", "Expected longer > shorter")

    if module._compare_prerelease([(True, 1)], [(True, 1)]) == 0:
        test_pass("registry prerelease length =")
    else:
        test_fail("registry prerelease length =", "Expected equal prerelease")

    result = module.CheckResult(blocked=True, message="test")
    if result.to_dict().get("blocked") is True:
        test_pass("registry result to_dict")
    else:
        test_fail("registry result to_dict", "Expected blocked True")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_registry = module.TSARegistry(cache_dir=tmpdir)
        if cache_registry.cache_dir and cache_registry.cache_dir.exists():
            test_pass("registry cache dir")
        else:
            test_fail("registry cache dir", "Cache dir missing")

    registry_sync = module.TSARegistry()
    sync_called = {"value": False}
    registry_sync.sync = lambda: sync_called.__setitem__("value", True) or {}
    registry_sync.subscribe_feed("feed.json", sync_now=True)
    if sync_called["value"]:
        test_pass("registry subscribe sync_now")
    else:
        test_fail("registry subscribe sync_now", "sync() not called")

    registry = module.TSARegistry()

    # _fetch_url http branch with monkeypatch
    import urllib.request

    class DummyResponse:
        def __init__(self, data: bytes):
            self._data = data

        def read(self):
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    original_urlopen = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda *_args, **_kwargs: DummyResponse(
            json.dumps({"advisories": []}).encode("utf-8")
        )
        if registry._fetch_url("https://example.test/feed.json") == {"advisories": []}:
            test_pass("registry fetch http")
        else:
            test_fail("registry fetch http", "Unexpected response")
    finally:
        urllib.request.urlopen = original_urlopen

    # resolve_url branches
    if (
        registry._resolve_url("https://example.test/feed.json", "a.json")
        == "https://example.test/a.json"
    ):
        test_pass("registry resolve http")
    else:
        test_fail("registry resolve http", "Unexpected URL")

    if (
        registry._resolve_url("http://example.test/feed.json", "a.json")
        == "http://example.test/a.json"
    ):
        test_pass("registry resolve http (non-ssl)")
    else:
        test_fail("registry resolve http (non-ssl)", "Unexpected URL")

    file_base = f"file://{REPO_ROOT / 'feeds' / 'sample-feed.json'}"
    resolved = registry._resolve_url(file_base, "advisory.json")
    if resolved.endswith("advisory.json"):
        test_pass("registry resolve file")
    else:
        test_fail("registry resolve file", "Unexpected file URL")

    local_resolved = registry._resolve_url(str(REPO_ROOT / "feeds" / "sample-feed.json"), "x.json")
    if local_resolved.endswith("x.json"):
        test_pass("registry resolve local")
    else:
        test_fail("registry resolve local", "Unexpected local URL")

    # _index_advisory with missing id
    registry._index_advisory({})
    test_pass("registry index missing id")

    # check_package handles missing affected list
    registry_missing = module.TSARegistry()
    registry_missing.advisories["TSA-MISSING-AFFECTED"] = {"id": "TSA-MISSING-AFFECTED"}
    registry_missing._package_index["pkg@npm"] = {"TSA-MISSING-AFFECTED"}
    try:
        result = registry_missing.check_package("pkg", "1.0.0", "npm")
        if not result.advisories:
            test_pass("registry check_package missing affected")
        else:
            test_fail("registry check_package missing affected", "Expected no advisories")
    except Exception as exc:
        test_fail("registry check_package missing affected", str(exc))

    # check_package handles missing tool entry
    registry_missing_tool = module.TSARegistry()
    registry_missing_tool.advisories["TSA-NO-TOOL"] = {
        "id": "TSA-NO-TOOL",
        "affected": [{"status": "AFFECTED"}],
    }
    registry_missing_tool._package_index["pkg@npm"] = {"TSA-NO-TOOL"}
    try:
        result = registry_missing_tool.check_package("pkg", "1.0.0", "npm")
        if not result.advisories:
            test_pass("registry check_package missing tool")
        else:
            test_fail("registry check_package missing tool", "Expected no advisories")
    except Exception as exc:
        test_fail("registry check_package missing tool", str(exc))

    # signature warning branches
    registry.require_signatures = True
    with contextlib.redirect_stderr(io.StringIO()):
        registry._index_advisory(
            {
                "id": "TSA-TEST-2025-0200",
                "actions": [{"type": "BLOCK"}],
                "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
            }
        )
        registry._index_advisory(
            {
                "id": "TSA-TEST-2025-0201",
                "signature": {"key_id": "unknown"},
                "actions": [{"type": "BLOCK"}],
                "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
            }
        )
    test_pass("registry signature warnings")
    # sync error branch
    registry_err = module.TSARegistry()
    registry_err.subscribe_feed("missing-feed.json")
    with contextlib.redirect_stderr(io.StringIO()):
        stats = registry_err.sync()
    if stats.get("errors"):
        test_pass("registry sync error")
    else:
        test_fail("registry sync error", "Expected error list")

    # _sync_feed entry exception
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        feed_path = tmp_path / "feed.json"
        feed_path.write_text(
            json.dumps(
                {
                    "feed_version": "1.0.0",
                    "generated": "2025-01-01T00:00:00Z",
                    "publisher": {"name": "Test", "namespace": "https://example.test"},
                    "advisories": [{"id": "bad", "advisory": "not-a-dict"}],
                }
            )
        )
        with contextlib.redirect_stderr(io.StringIO()):
            registry._sync_feed(str(feed_path))
        test_pass("registry sync feed entry exception")

    with tempfile.TemporaryDirectory() as tmpdir:
        feed_path = Path(tmpdir) / "feed.json"
        feed_path.write_text(
            json.dumps(
                {
                    "feed_version": "1.0.0",
                    "generated": "2025-01-01T00:00:00Z",
                    "publisher": {"name": "Test", "namespace": "https://example.test"},
                    "advisories": [{"id": "no-advisory"}],
                }
            )
        )
        registry._sync_feed(str(feed_path))
        test_pass("registry sync skip missing advisory")

    with tempfile.TemporaryDirectory() as tmpdir:
        feed_path = Path(tmpdir) / "feed.json"
        advisory = {
            "id": "TSA-TEST-2025-0999",
            "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
        }
        feed_path.write_text(
            json.dumps(
                {
                    "feed_version": "1.0.0",
                    "generated": "2025-01-01T00:00:00Z",
                    "publisher": {"name": "Test", "namespace": "https://example.test"},
                    "advisories": [{"id": advisory["id"], "advisory": advisory}],
                }
            )
        )
        registry.add_advisory(advisory)
        stats = registry._sync_feed(str(feed_path))
        if stats.get("updated") == 1:
            test_pass("registry sync updated")
        else:
            test_fail("registry sync updated", "Expected updated=1")

    # check_package condition mismatch and WARN action
    advisory = {
        "id": "TSA-TEST-2025-0202",
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"affected_range": ">=1.0.0 <2.0.0"},
                "status": "AFFECTED",
            }
        ],
        "actions": [
            {"type": "WARN", "condition": ">=2.0.0", "message": "Skip"},
            {"type": "WARN", "message": "Warn"},
        ],
    }
    registry = module.TSARegistry()
    registry.add_advisory(advisory)
    result = registry.check_package("demo", "1.5.0", "npm")
    if result.warnings and "Warn" in result.warnings[-1]:
        test_pass("registry condition mismatch")
    else:
        test_fail("registry condition mismatch", "Expected WARN action applied")

    registry_missing = module.TSARegistry()
    registry_missing._package_index["demo@npm"] = {"missing"}
    registry_missing.check_package("demo", "1.0.0", "npm")
    test_pass("registry missing advisory")

    registry_mismatch = module.TSARegistry()
    registry_mismatch.advisories["adv-name"] = {
        "affected": [{"tool": {"name": "other", "registry": "npm"}, "status": "AFFECTED"}]
    }
    registry_mismatch._package_index["demo@npm"] = {"adv-name"}
    registry_mismatch.check_package("demo", "1.0.0", "npm")
    test_pass("registry tool name mismatch")

    registry_reg_mismatch = module.TSARegistry()
    registry_reg_mismatch.advisories["adv-reg"] = {
        "affected": [{"tool": {"name": "demo", "registry": "pypi"}, "status": "AFFECTED"}]
    }
    registry_reg_mismatch._package_index["demo@npm"] = {"adv-reg"}
    registry_reg_mismatch.check_package("demo", "1.0.0", "npm")
    test_pass("registry tool registry mismatch")

    if registry._version_affected("1.0.0", {"status": "NOT_AFFECTED"}) is False:
        test_pass("registry status not affected")
    else:
        test_fail("registry status not affected", "Expected False")

    if (
        registry._version_affected(
            "1.1.0", {"status": "AFFECTED", "versions": {"last_affected": "1.0.0"}}
        )
        is False
    ):
        test_pass("registry last_affected exclusion")
    else:
        test_fail("registry last_affected exclusion", "Expected False")

    if registry._matches_range("1.0.0", ">1.2.0") is False:
        test_pass("registry range >")
    else:
        test_fail("registry range >", "Expected False")

    if registry._matches_range("2.0.0", "<=1.0.0") is False:
        test_pass("registry range <=")
    else:
        test_fail("registry range <=", "Expected False")

    if registry._matches_range("1.0.1", "=1.0.0") is False:
        test_pass("registry range =")
    else:
        test_fail("registry range =", "Expected False")

    class _RangeStub:
        def replace(self, *_args, **_kwargs):
            return self

        def split(self):
            return ["", ">=1.0.0"]

    original_re_sub = module.re.sub
    module.re.sub = lambda *_args, **_kwargs: _RangeStub()
    try:
        if registry._matches_range("1.0.0", ">=1.0.0") is True:
            test_pass("registry range empty part")
        else:
            test_fail("registry range empty part", "Expected True")
    finally:
        module.re.sub = original_re_sub

    if registry._compare_versions("release-2", "release-10") < 0:
        test_pass("registry compare fallback <")
    else:
        test_fail("registry compare fallback <", "Expected <")

    if registry._compare_versions("release-10", "release-2") > 0:
        test_pass("registry compare fallback >")
    else:
        test_fail("registry compare fallback >", "Expected >")

    if registry._compare_versions("release-1", "release-1") == 0:
        test_pass("registry compare fallback =")
    else:
        test_fail("registry compare fallback =", "Expected =")

    # __main__ demo branch
    try:
        runpy.run_path(str(resolve_tool_script("tsa_registry_sdk.py")), run_name="__main__")
        test_pass("registry __main__ demo")
    except SystemExit:
        test_pass("registry __main__ demo")


# =============================================================================
# Registry Core Direct Checks
# =============================================================================


def test_registry_core_direct_checks():
    """Directly target tsa_registry_sdk_core branches for mutation coverage."""
    log("\n=== Registry Core Direct Checks ===")

    try:
        import tools.tsa_registry_sdk_core as core
    except ImportError as exc:
        test_fail("registry core import", str(exc))
        return

    if core._compare_prerelease([(True, 2)], [(True, 1)]) == 1:
        test_pass("registry core prerelease numeric >")
    else:
        test_fail("registry core prerelease numeric >", "Expected 2 > 1")

    registry = core.TSARegistry()
    if (
        registry._resolve_url("https://example.test/feed.json", "a.json")
        == "https://example.test/a.json"
    ):
        test_pass("registry core resolve http")
    else:
        test_fail("registry core resolve http", "Unexpected URL")

    if (
        registry._resolve_url("http://example.test/feed.json", "a.json")
        == "http://example.test/a.json"
    ):
        test_pass("registry core resolve http (non-ssl)")
    else:
        test_fail("registry core resolve http (non-ssl)", "Unexpected URL")

    file_base = f"file://{REPO_ROOT / 'feeds' / 'sample-feed.json'}"
    resolved = registry._resolve_url(file_base, "advisory.json")
    if resolved.endswith("advisory.json"):
        test_pass("registry core resolve file")
    else:
        test_fail("registry core resolve file", "Unexpected file URL")

    local_resolved = registry._resolve_url(str(REPO_ROOT / "feeds" / "sample-feed.json"), "x.json")
    if local_resolved.endswith("x.json"):
        test_pass("registry core resolve local")
    else:
        test_fail("registry core resolve local", "Unexpected local URL")

    registry_missing = core.TSARegistry()
    registry_missing.advisories["TSA-MISSING-AFFECTED"] = {"id": "TSA-MISSING-AFFECTED"}
    registry_missing._package_index["pkg@npm"] = {"TSA-MISSING-AFFECTED"}
    result = registry_missing.check_package("pkg", "1.0.0", "npm")
    if not result.advisories:
        test_pass("registry core check_package missing affected")
    else:
        test_fail("registry core check_package missing affected", "Expected no advisories")

    registry_missing_tool = core.TSARegistry()
    registry_missing_tool.advisories["TSA-NO-TOOL"] = {
        "id": "TSA-NO-TOOL",
        "affected": [{"status": "AFFECTED"}],
    }
    registry_missing_tool._package_index["pkg@npm"] = {"TSA-NO-TOOL"}
    result = registry_missing_tool.check_package("pkg", "1.0.0", "npm")
    if not result.advisories:
        test_pass("registry core check_package missing tool")
    else:
        test_fail("registry core check_package missing tool", "Expected no advisories")

    registry_name_mismatch = core.TSARegistry()
    registry_name_mismatch.advisories["adv-name"] = {
        "affected": [{"tool": {"name": "other", "registry": "npm"}, "status": "AFFECTED"}]
    }
    registry_name_mismatch._package_index["demo@npm"] = {"adv-name"}
    result = registry_name_mismatch.check_package("demo", "1.0.0", "npm")
    if not result.advisories:
        test_pass("registry core tool name mismatch")
    else:
        test_fail("registry core tool name mismatch", "Expected no advisories")

    registry_reg_mismatch = core.TSARegistry()
    registry_reg_mismatch.advisories["adv-reg"] = {
        "affected": [{"tool": {"name": "demo", "registry": "pypi"}, "status": "AFFECTED"}]
    }
    registry_reg_mismatch._package_index["demo@npm"] = {"adv-reg"}
    result = registry_reg_mismatch.check_package("demo", "1.0.0", "npm")
    if not result.advisories:
        test_pass("registry core tool registry mismatch")
    else:
        test_fail("registry core tool registry mismatch", "Expected no advisories")

    registry_condition = core.TSARegistry()
    registry_condition.advisories["adv-condition"] = {
        "id": "adv-condition",
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm"},
                "versions": {"affected_range": ">=1.0.0 <2.0.0"},
                "status": "AFFECTED",
            }
        ],
        "actions": [
            {"type": "WARN", "condition": ">=2.0.0", "message": "Skip"},
        ],
    }
    registry_condition._package_index["demo@npm"] = {"adv-condition"}
    result = registry_condition.check_package("demo", "1.5.0", "npm")
    if not result.actions and not result.warnings:
        test_pass("registry core condition mismatch")
    else:
        test_fail("registry core condition mismatch", "Expected no actions for mismatch")

    if registry._compare_versions("1.0.0-2", "1.0.0-1") == 1:
        test_pass("registry core compare_versions prerelease exact")
    else:
        test_fail("registry core compare_versions prerelease exact", "Expected exact return of 1")

    if core._compare_prerelease([(False, "b")], [(False, "a")]) == 1:
        test_pass("registry core prerelease string exact")
    else:
        test_fail("registry core prerelease string exact", "Expected exact return of 1")

    if registry._matches_range("1.0.0", ">=1.0.0,<=2.0.0"):
        test_pass("registry core matches_range commas")
    else:
        test_fail("registry core matches_range commas", "Expected comma range match")

    if registry._matches_condition("1.0.0", ">=1.0.0,<=2.0.0"):
        test_pass("registry core matches_condition commas")
    else:
        test_fail("registry core matches_condition commas", "Expected comma condition match")

    if core.CRYPTO_AVAILABLE:
        try:
            from tools import tsactl_core
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        except ImportError as exc:
            test_fail("registry core signature imports", str(exc))
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                priv_path, pub_path = tsactl_core.generate_keys(os.path.join(tmpdir, "sig"))
                pub_pem = Path(pub_path).read_text()
                anchor_full = core.TrustAnchor(
                    key_id="sig:key1", public_key=pub_pem, publisher="Test", trust_level="full"
                )

                try:
                    registry._load_public_key("")
                    test_fail("registry core empty public key", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Empty public key":
                        test_pass("registry core empty public key")
                    else:
                        test_fail("registry core empty public key", str(exc))

                try:
                    registry._load_public_key("A")
                    test_fail("registry core invalid public key encoding", "Expected ValueError")
                except ValueError as exc:
                    if str(exc) == "Invalid public key encoding":
                        test_pass("registry core invalid public key encoding")
                    else:
                        test_fail("registry core invalid public key encoding", str(exc))

                advisory = {
                    "id": "TSA-SIG-0001",
                    "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
                    "actions": [{"type": "BLOCK", "message": "Block demo", "urgency": "IMMEDIATE"}],
                }
                signed = tsactl_core.sign_document(advisory, priv_path, "sig:key1")

                ok, reason = registry._verify_signature(signed, anchor_full)
                if ok and reason == "":
                    test_pass("registry core verify signature")
                else:
                    test_fail("registry core verify signature", f"{ok} {reason}")

                canonical = tsactl_core.canonicalize(advisory).encode("utf-8")

                rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                rsa_public = rsa_private.public_key()
                rsa_sig = rsa_private.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
                rsa_doc = dict(advisory)
                rsa_doc["signature"] = {
                    "algorithm": "RS256",
                    "key_id": "sig:rsa",
                    "value": base64.b64encode(rsa_sig).decode("ascii"),
                }
                rsa_pub_pem = rsa_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                anchor_rsa = core.TrustAnchor(
                    key_id="sig:rsa", public_key=rsa_pub_pem, publisher="Test", trust_level="full"
                )
                ok, reason = registry._verify_signature(rsa_doc, anchor_rsa)
                if ok and reason == "":
                    test_pass("registry core verify signature RS256")
                else:
                    test_fail("registry core verify signature RS256", f"{ok} {reason}")

                ec256_private = ec.generate_private_key(ec.SECP256R1())
                ec256_public = ec256_private.public_key()
                ec256_sig = ec256_private.sign(canonical, ec.ECDSA(hashes.SHA256()))
                ec256_doc = dict(advisory)
                ec256_doc["signature"] = {
                    "algorithm": "ES256",
                    "key_id": "sig:ec256",
                    "value": base64.b64encode(ec256_sig).decode("ascii"),
                }
                ec256_pub_pem = ec256_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                anchor_ec256 = core.TrustAnchor(
                    key_id="sig:ec256",
                    public_key=ec256_pub_pem,
                    publisher="Test",
                    trust_level="full",
                )
                ok, reason = registry._verify_signature(ec256_doc, anchor_ec256)
                if ok and reason == "":
                    test_pass("registry core verify signature ES256")
                else:
                    test_fail("registry core verify signature ES256", f"{ok} {reason}")

                ec384_private = ec.generate_private_key(ec.SECP384R1())
                ec384_public = ec384_private.public_key()
                ec384_sig = ec384_private.sign(canonical, ec.ECDSA(hashes.SHA384()))
                ec384_doc = dict(advisory)
                ec384_doc["signature"] = {
                    "algorithm": "ES384",
                    "key_id": "sig:ec384",
                    "value": base64.b64encode(ec384_sig).decode("ascii"),
                }
                ec384_pub_pem = ec384_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                anchor_ec384 = core.TrustAnchor(
                    key_id="sig:ec384",
                    public_key=ec384_pub_pem,
                    publisher="Test",
                    trust_level="full",
                )
                ok, reason = registry._verify_signature(ec384_doc, anchor_ec384)
                if ok and reason == "":
                    test_pass("registry core verify signature ES384")
                else:
                    test_fail("registry core verify signature ES384", f"{ok} {reason}")

                ed_key_mismatch = json.loads(json.dumps(signed))
                ed_key_mismatch["signature"]["key_id"] = "sig:rsa"
                ok, reason = registry._verify_signature(ed_key_mismatch, anchor_rsa)
                if not ok and reason == "invalid public key: expected Ed25519":
                    test_pass("registry core Ed25519 key type mismatch")
                else:
                    test_fail(
                        "registry core Ed25519 key type mismatch",
                        f"Unexpected: {reason}",
                    )

                es256_with_rsa = json.loads(json.dumps(ec256_doc))
                es256_with_rsa["signature"]["key_id"] = "sig:rsa"
                ok, reason = registry._verify_signature(es256_with_rsa, anchor_rsa)
                if not ok and reason == "invalid public key: expected P-256":
                    test_pass("registry core ES256 key type mismatch")
                else:
                    test_fail(
                        "registry core ES256 key type mismatch",
                        f"Unexpected: {reason}",
                    )

                es256_wrong_curve = json.loads(json.dumps(ec256_doc))
                es256_wrong_curve["signature"]["key_id"] = "sig:ec384"
                ok, reason = registry._verify_signature(es256_wrong_curve, anchor_ec384)
                if not ok and reason == "invalid public key: expected P-256":
                    test_pass("registry core ES256 wrong curve")
                else:
                    test_fail(
                        "registry core ES256 wrong curve",
                        f"Unexpected: {reason}",
                    )

                es384_with_rsa = json.loads(json.dumps(ec384_doc))
                es384_with_rsa["signature"]["key_id"] = "sig:rsa"
                ok, reason = registry._verify_signature(es384_with_rsa, anchor_rsa)
                if not ok and reason == "invalid public key: expected P-384":
                    test_pass("registry core ES384 key type mismatch")
                else:
                    test_fail(
                        "registry core ES384 key type mismatch",
                        f"Unexpected: {reason}",
                    )

                es384_wrong_curve = json.loads(json.dumps(ec384_doc))
                es384_wrong_curve["signature"]["key_id"] = "sig:ec256"
                ok, reason = registry._verify_signature(es384_wrong_curve, anchor_ec256)
                if not ok and reason == "invalid public key: expected P-384":
                    test_pass("registry core ES384 wrong curve")
                else:
                    test_fail(
                        "registry core ES384 wrong curve",
                        f"Unexpected: {reason}",
                    )

                pub_obj = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
                der = pub_obj.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                raw = pub_obj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                raw_b64 = base64.b64encode(raw).decode("ascii")
                try:
                    registry._load_public_key(raw_b64)
                    test_pass("registry core raw public key")
                except Exception as exc:
                    test_fail("registry core raw public key", str(exc))

                pub_b64 = base64.b64encode(der).decode("ascii")
                anchor_b64 = core.TrustAnchor(
                    key_id="sig:key1", public_key=pub_b64, publisher="Test", trust_level="full"
                )
                ok, _ = registry._verify_signature(signed, anchor_b64)
                if ok:
                    test_pass("registry core verify base64 key")
                else:
                    test_fail("registry core verify base64 key", "Expected base64 key to work")

                tampered = json.loads(json.dumps(signed))
                tampered["signature"]["value"] = "AA=="
                ok, reason = registry._verify_signature(tampered, anchor_full)
                if not ok and reason == "invalid signature":
                    test_pass("registry core invalid signature")
                else:
                    test_fail("registry core invalid signature", f"Unexpected: {reason}")

                bad_encoding = json.loads(json.dumps(signed))
                bad_encoding["signature"]["value"] = "A"
                ok, reason = registry._verify_signature(bad_encoding, anchor_full)
                if not ok and reason == "invalid signature encoding":
                    test_pass("registry core invalid signature encoding")
                else:
                    test_fail("registry core invalid signature encoding", f"Unexpected: {reason}")

                bad_alg = json.loads(json.dumps(signed))
                bad_alg["signature"]["algorithm"] = "NOPE"
                ok, reason = registry._verify_signature(bad_alg, anchor_full)
                if not ok and reason == "unsupported algorithm: NOPE":
                    test_pass("registry core unsupported algorithm")
                else:
                    test_fail("registry core unsupported algorithm", f"Unexpected: {reason}")

                key_type_mismatch = json.loads(json.dumps(signed))
                key_type_mismatch["signature"]["algorithm"] = "RS256"
                ok, reason = registry._verify_signature(key_type_mismatch, anchor_full)
                if not ok and reason == "invalid public key: expected RSA":
                    test_pass("registry core key type mismatch")
                else:
                    test_fail("registry core key type mismatch", f"Unexpected: {reason}")

                key_mismatch = json.loads(json.dumps(signed))
                key_mismatch["signature"]["key_id"] = "sig:other"
                ok, reason = registry._verify_signature(key_mismatch, anchor_full)
                if not ok and reason == "key_id mismatch":
                    test_pass("registry core key_id mismatch")
                else:
                    test_fail("registry core key_id mismatch", f"Unexpected: {reason}")

                missing_value = json.loads(json.dumps(signed))
                missing_value["signature"].pop("value", None)
                ok, reason = registry._verify_signature(missing_value, anchor_full)
                if not ok and reason == "missing signature value":
                    test_pass("registry core missing signature value")
                else:
                    test_fail("registry core missing signature value", f"Unexpected: {reason}")

                ok, reason = registry._verify_signature(advisory, anchor_full)
                if not ok and reason == "unsigned":
                    test_pass("registry core missing signature")
                else:
                    test_fail("registry core missing signature", f"Unexpected: {reason}")

                anchor_bad = core.TrustAnchor(
                    key_id="sig:key1", public_key="A", publisher="Test", trust_level="full"
                )
                ok, reason = registry._verify_signature(signed, anchor_bad)
                if not ok and reason == "invalid public key: Invalid public key encoding":
                    test_pass("registry core invalid public key")
                else:
                    test_fail("registry core invalid public key", f"Unexpected: {reason}")

                registry_invalid = core.TSARegistry(require_signatures=True)
                registry_invalid.trust_anchors["sig:key1"] = anchor_full
                registry_invalid.add_advisory(tampered)
                result_invalid = registry_invalid.check_package("demo", "0.1.0", "npm")
                expected_invalid = "[WARN instead of BLOCK - invalid signature] Block demo"
                if result_invalid.warnings == [expected_invalid]:
                    test_pass("registry core invalid signature warning")
                else:
                    test_fail(
                        "registry core invalid signature warning",
                        f"Warnings: {result_invalid.warnings}",
                    )

                registry_bad_encoding = core.TSARegistry(require_signatures=True)
                registry_bad_encoding.trust_anchors["sig:key1"] = anchor_full
                registry_bad_encoding.add_advisory(bad_encoding)
                result_bad_encoding = registry_bad_encoding.check_package("demo", "0.1.0", "npm")
                expected_encoding = (
                    "[WARN instead of BLOCK - invalid signature encoding] Block demo"
                )
                if result_bad_encoding.warnings == [expected_encoding]:
                    test_pass("registry core invalid encoding warning")
                else:
                    test_fail(
                        "registry core invalid encoding warning",
                        f"Warnings: {result_bad_encoding.warnings}",
                    )

                registry_fallback = core.TSARegistry(require_signatures=True)
                registry_fallback.trust_anchors["sig:key1"] = anchor_full
                registry_fallback.add_advisory(signed)
                original_verify = registry_fallback._verify_signature
                registry_fallback._verify_signature = lambda *_a, **_k: (False, "")
                try:
                    result_fallback = registry_fallback.check_package("demo", "0.1.0", "npm")
                    expected_fallback = "[WARN instead of BLOCK - invalid signature] Block demo"
                    if result_fallback.warnings == [expected_fallback]:
                        test_pass("registry core invalid signature fallback")
                    else:
                        test_fail(
                            "registry core invalid signature fallback",
                            f"Warnings: {result_fallback.warnings}",
                        )
                finally:
                    registry_fallback._verify_signature = original_verify

                registry_unsigned = core.TSARegistry(require_signatures=True)
                registry_unsigned.add_advisory(advisory)
                result_unsigned = registry_unsigned.check_package("demo", "0.1.0", "npm")
                expected_unsigned = "[WARN instead of BLOCK - unsigned] Block demo"
                if result_unsigned.warnings == [expected_unsigned]:
                    test_pass("registry core unsigned warning")
                else:
                    test_fail(
                        "registry core unsigned warning",
                        f"Warnings: {result_unsigned.warnings}",
                    )

                registry_missing_key = core.TSARegistry(require_signatures=True)
                registry_missing_key.trust_anchors["sig:key1"] = anchor_full
                missing_key = json.loads(json.dumps(advisory))
                missing_key["signature"] = {"algorithm": "Ed25519", "value": "AA=="}
                registry_missing_key.add_advisory(missing_key)
                result_missing_key = registry_missing_key.check_package("demo", "0.1.0", "npm")
                expected_missing = "[WARN instead of BLOCK - missing key_id] Block demo"
                if result_missing_key.warnings == [expected_missing]:
                    test_pass("registry core missing key_id warning")
                else:
                    test_fail(
                        "registry core missing key_id warning",
                        f"Warnings: {result_missing_key.warnings}",
                    )

                registry_unknown = core.TSARegistry(require_signatures=True)
                unknown_sig = json.loads(json.dumps(advisory))
                unknown_sig["signature"] = {
                    "algorithm": "Ed25519",
                    "key_id": "unknown",
                    "value": "AA==",
                }
                registry_unknown.add_advisory(unknown_sig)
                result_unknown = registry_unknown.check_package("demo", "0.1.0", "npm")
                expected_unknown = "[WARN instead of BLOCK - unknown signer] Block demo"
                if result_unknown.warnings == [expected_unknown]:
                    test_pass("registry core unknown signer warning")
                else:
                    test_fail(
                        "registry core unknown signer warning",
                        f"Warnings: {result_unknown.warnings}",
                    )

                registry_warn = core.TSARegistry(require_signatures=True)
                registry_warn.trust_anchors["sig:key1"] = core.TrustAnchor(
                    key_id="sig:key1",
                    public_key=pub_pem,
                    publisher="Test",
                    trust_level="warn_only",
                )
                registry_warn.add_advisory(signed)
                result_warn = registry_warn.check_package("demo", "0.1.0", "npm")
                expected_warn = "[WARN instead of BLOCK - trust_level=warn_only] Block demo"
                if not result_warn.blocked and result_warn.warnings == [expected_warn]:
                    test_pass("registry core warn_only trust level")
                else:
                    test_fail(
                        "registry core warn_only trust level",
                        f"Warnings: {result_warn.warnings}",
                    )

                original_crypto = core.CRYPTO_AVAILABLE
                core.CRYPTO_AVAILABLE = False
                ok, reason = registry._verify_signature(signed, anchor_full)
                if not ok and reason == "cryptography not available":
                    test_pass("registry core crypto unavailable")
                else:
                    test_fail("registry core crypto unavailable", f"Unexpected: {reason}")
                core.CRYPTO_AVAILABLE = original_crypto


# =============================================================================
# Integration Tests
# =============================================================================


def test_full_workflow():
    """Test complete workflow: validate, sign, verify, match."""
    log("\n=== Full Workflow Integration Test ===")

    try:
        from tools.tsactl_core import (
            generate_keys,
            match_advisory,
            sign_document,
            validate_tsa,
            verify_signature,
        )
        from tools.tsa_registry_sdk import TSARegistry
    except ImportError:
        test_fail("Workflow imports", "Could not import required modules")
        return

    # Load a real advisory
    advisory_path = REPO_ROOT / "advisories" / "TSA-2025-0001-mcp-remote-rce.tsa.json"
    if not advisory_path.exists():
        test_fail("Workflow", "Advisory file not found")
        return

    try:
        with open(advisory_path) as f:
            advisory = json.load(f)
    except Exception as e:
        test_fail("Workflow load", str(e))
        return

    # Step 1: Validate
    result = validate_tsa(advisory)
    if result.valid:
        test_pass("Workflow: validate")
    else:
        test_fail("Workflow: validate", result.summary())
        return

    # Step 2: Sign
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            priv_path, pub_path = generate_keys(os.path.join(tmpdir, "wf"))
            signed = sign_document(advisory, priv_path, "workflow:test")
            test_pass("Workflow: sign")
        except Exception as e:
            test_fail("Workflow: sign", str(e))
            return

        # Step 3: Verify
        try:
            if verify_signature(signed, pub_path):
                test_pass("Workflow: verify")
            else:
                test_fail("Workflow: verify", "Verification failed")
                return
        except Exception as e:
            test_fail("Workflow: verify", str(e))
            return

    # Step 4: Match against inventory
    inventory = [
        {"name": "mcp-remote", "version": "0.1.14", "registry": "npm"},
        {"name": "mcp-remote", "version": "0.1.16", "registry": "npm"},
    ]

    try:
        matches = match_advisory(advisory, inventory)
        if len(matches) == 1 and matches[0]["version"] == "0.1.14":
            test_pass("Workflow: match")
        else:
            test_fail("Workflow: match", f"Expected 1 match for 0.1.14, got {len(matches)}")
    except Exception as e:
        test_fail("Workflow: match", str(e))
        return

    # Step 5: SDK integration
    try:
        registry = TSARegistry()
        registry.add_advisory(advisory)
        result = registry.check_package("mcp-remote", "0.1.14", "npm")
        if result.blocked:
            test_pass("Workflow: SDK enforcement")
        else:
            test_fail("Workflow: SDK enforcement", "Should block vulnerable version")
    except Exception as e:
        test_fail("Workflow: SDK", str(e))


# =============================================================================
# Main
# =============================================================================


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(description="TSA Specification Test Harness")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    passed, failed = run_all(verbose=args.verbose)
    return 0 if failed == 0 else 1


def run_all(verbose: bool = False):
    global VERBOSE, PASSED, FAILED

    VERBOSE = verbose
    PASSED = 0
    FAILED = 0
    previous_cwd = os.getcwd()
    os.chdir(REPO_ROOT)

    try:
        print("=" * 60)
        print("TSA Specification Test Suite v1.0.0")
        print("=" * 60)

        # Run all test suites
        test_schema_validity()
        test_schema_strictness()
        test_advisory_validation()
        test_advisory_cve_format()
        test_feed_validation()
        test_feed_hash_integrity()
        test_tsactl_validate()
        test_tsactl_canonicalize()
        test_tsactl_signing()
        test_tsactl_error_branches()
        test_tsactl_schema_error_ordering()
        test_tsactl_semantics_positive()
        test_tsactl_semantics_edge_cases()
        test_tsactl_match_bounds()
        test_tsactl_missing_imports()
        test_tsactl_version_helpers()
        test_version_matching_bounds()
        test_osv_converter_roundtrip()
        test_osv_converter_edge_cases()
        test_osv_converter_golden()
        test_osv_converter_mapping_tables()
        test_build_feed_inline()
        test_build_feed_golden()
        test_build_feed_fallback()
        test_build_feed_variants()
        test_cli_e2e()
        test_cli_entrypoints_in_process()
        test_registry_sdk()
        test_registry_feed_sync()
        test_registry_feed_sync_edge_cases()
        test_registry_signature_policy()
        test_registry_action_handling()
        test_registry_sdk_edge_cases()
        test_registry_core_direct_checks()
        test_full_workflow()

        # Summary
        print("\n" + "=" * 60)
        print(f"RESULTS: {PASSED} passed, {FAILED} failed")
        print("=" * 60)

        if FAILED == 0:
            print("\n✓ ALL TESTS PASSED")
        else:
            print(f"\n✗ {FAILED} TEST(S) FAILED")
    finally:
        os.chdir(previous_cwd)

    return PASSED, FAILED


if __name__ == "__main__":
    sys.exit(main())
