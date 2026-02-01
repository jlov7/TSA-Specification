from __future__ import annotations

import base64
import json
import os
import tempfile
import zlib
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

import tools.build_feed_core as build_feed_core
import tools.osv_converter_core as osv_converter_core
import tools.tsa_registry_sdk_core as registry_core
import tools.tsactl_core as tsactl_core


def _repo_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root.parent if root.name == "mutants" else root


def test_validate_semantics_warnings_and_errors_exact():
    doc = {
        "tsa_version": "0.9.0",
        "published": "2025-01-02T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
    }
    errors, warnings = tsactl_core.validate_semantics(doc)
    assert errors == ["modified timestamp cannot be before published timestamp"]
    assert warnings == [
        "tsa_version '0.9.0' is not '1.0.0'",
        "No entries with AFFECTED status - is this advisory actionable?",
        "No BLOCK or WARN actions - registries may not enforce this advisory",
        "No CVE or ADVISORY references - consider adding authoritative sources",
        "No severity information - registries need this for prioritization",
    ]


def test_validate_semantics_specific_warnings():
    doc = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {"status": "AFFECTED", "tool": {"name": "demo"}, "versions": {}},
        ],
        "actions": [{"type": "WARN"}],
        "references": [{"type": "CVE", "id": "CVE-2025-0001"}],
        "severity": {"cvss_v3": {"vector": "CVSS:3.1/AV:N", "score": 5.0}},
    }
    errors, warnings = tsactl_core.validate_semantics(doc)
    assert errors == []
    assert warnings == [
        "affected[0]: AFFECTED status but no version constraints",
        "actions[0]: WARN action should have a message",
    ]


def test_validate_semantics_cvss_warning_only():
    doc = {
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
        "actions": [{"type": "BLOCK", "message": "Block"}],
        "references": [{"type": "ADVISORY", "url": "https://example.test"}],
        "severity": {"qualitative": "HIGH"},
    }
    errors, warnings = tsactl_core.validate_semantics(doc)
    assert errors == []
    assert warnings == ["No CVSS score - consider adding for interoperability"]


def test_canonicalize_edge_cases():
    cases = [
        ({"b": True, "a": False}, '{"a":false,"b":true}'),
        ({"num": 1.0, "text": "x"}, '{"num":1,"text":"x"}'),
        ({"float": 1.2300}, '{"float":1.23}'),
        ({"list": [1, None, "x"]}, '{"list":[1,null,"x"]}'),
        ({"unicode": "é"}, '{"unicode":"é"}'),
    ]
    for doc, expected in cases:
        assert tsactl_core.canonicalize(doc) == expected


def test_find_schema_path_resolves_repo_schema():
    repo_root = _repo_root()
    expected = (repo_root / "schema" / "tsa-v1.0.0.schema.json").resolve()
    cwd = os.getcwd()
    os.chdir(repo_root)
    try:
        path = tsactl_core.find_schema_path()
    finally:
        os.chdir(cwd)
    assert path is not None
    assert path.resolve() == expected


def test_validate_schema_errors_when_available():
    if not tsactl_core.JSONSCHEMA_AVAILABLE:
        pytest.skip("jsonschema not available")

    bad_schema = {"type": "object", "properties": {"a": {"type": "unknown"}}}
    errors = tsactl_core.validate_schema({"a": "x"}, bad_schema)
    assert errors and errors[0].startswith("Invalid schema:")

    schema = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "required": ["a"],
        "additionalProperties": False,
    }
    errors = tsactl_core.validate_schema({"a": 1, "b": 2}, schema)
    assert any("Additional properties are not allowed" in e for e in errors)
    assert any("[a]" in e for e in errors)


def test_validate_tsa_reports_schema_errors():
    if not tsactl_core.JSONSCHEMA_AVAILABLE:
        pytest.skip("jsonschema not available")

    repo_root = _repo_root()
    cwd = os.getcwd()
    os.chdir(repo_root)
    try:
        result = tsactl_core.validate_tsa({"tsa_version": "1.0.0"})
    finally:
        os.chdir(cwd)
    assert result.valid is False
    assert result.schema_errors
    assert all(isinstance(err, str) for err in result.schema_errors)


def test_tsactl_compare_prerelease_cases():
    assert tsactl_core._compare_prerelease([], []) == 0
    assert tsactl_core._compare_prerelease([(True, 1)], [(True, 2)]) == -1
    assert tsactl_core._compare_prerelease([(True, 2)], [(True, 1)]) == 1
    assert tsactl_core._compare_prerelease([(True, 1)], [(False, "a")]) == -1
    assert tsactl_core._compare_prerelease([(False, "b")], [(True, 1)]) == 1
    assert tsactl_core._compare_prerelease([(False, "a")], [(False, "b")]) == -1
    assert tsactl_core._compare_prerelease([(True, 1), (False, "a")], [(True, 1)]) == 1


def test_tsactl_version_in_range_cases():
    assert tsactl_core.version_in_range("1.2.3", ">=1.0.0 <2.0.0") is True
    assert tsactl_core.version_in_range("2.0.0", ">=1.0.0 <2.0.0") is False
    assert tsactl_core.version_in_range("1.2.3", "=1.2.3") is True
    assert tsactl_core.version_in_range("1.2.3", "1.2.4") is False


def test_match_advisory_exact_matches():
    tsa_doc = {
        "id": "TSA-TEST-1234",
        "severity": {"qualitative": "HIGH"},
        "affected": [
            {
                "tool": {"name": "alpha", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
                "impact_statement": "Impact A",
            },
            {
                "tool": {"name": "alpha"},
                "status": "AFFECTED",
                "versions": {"affected_range": ">=2.0.0 <3.0.0"},
                "impact_statement": "Impact B",
            },
            {
                "tool": {"name": "beta", "registry": "pypi"},
                "status": "NOT_AFFECTED",
                "versions": {"introduced": "0.1.0"},
            },
        ],
    }
    inventory = [
        {"name": "alpha", "version": "1.5.0", "registry": "npm"},
        {"name": "alpha", "version": "2.5.0", "registry": "npm"},
        {"name": "alpha", "version": "3.0.0", "registry": "npm"},
    ]

    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert matches == [
        {
            "tool": "alpha",
            "version": "1.5.0",
            "registry": "npm",
            "advisory_id": "TSA-TEST-1234",
            "status": "AFFECTED",
            "severity": "HIGH",
            "impact": "Impact A",
            "fixed_version": "2.0.0",
        },
        {
            "tool": "alpha",
            "version": "2.5.0",
            "registry": "npm",
            "advisory_id": "TSA-TEST-1234",
            "status": "AFFECTED",
            "severity": "HIGH",
            "impact": "Impact B",
            "fixed_version": "N/A",
        },
    ]


def test_sign_document_details_and_changes():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path, pub_path = tsactl_core.generate_keys(os.path.join(tmpdir, "key"))

        doc_a = {"tsa_version": "1.0.0", "id": "TSA-TEST-A"}
        doc_b = {"tsa_version": "1.0.0", "id": "TSA-TEST-B"}

        signed_a = tsactl_core.sign_document(doc_a, priv_path, "test:key")
        signed_b = tsactl_core.sign_document(doc_b, priv_path, "test:key")

        assert signed_a["signature"]["algorithm"] == "Ed25519"
        assert signed_a["signature"]["key_id"] == "test:key"
        assert signed_a["signature"]["value"]
        assert signed_a["signature"]["value"] != signed_b["signature"]["value"]
        assert "timestamp" in signed_a["signature"]
        assert tsactl_core.verify_signature(signed_a, pub_path) is True

        tampered = json.loads(json.dumps(signed_a))
        tampered["id"] = "TSA-TEST-TAMPER"
        assert tsactl_core.verify_signature(tampered, pub_path) is False


def test_verify_signature_rsa_and_ecdsa():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    base_doc = {"tsa_version": "1.0.0", "id": "TSA-TEST-ALG"}
    canonical = tsactl_core.canonicalize(base_doc).encode("utf-8")

    with tempfile.TemporaryDirectory() as tmpdir:
        rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_public = rsa_private.public_key()
        rsa_sig = rsa_private.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
        rsa_doc = dict(base_doc)
        rsa_doc["signature"] = {
            "algorithm": "RS256",
            "key_id": "test:rsa",
            "value": base64.b64encode(rsa_sig).decode("ascii"),
        }
        rsa_pub_path = os.path.join(tmpdir, "rsa.pem")
        with open(rsa_pub_path, "wb") as handle:
            handle.write(
                rsa_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        assert tsactl_core.verify_signature(rsa_doc, rsa_pub_path) is True

        ec256_private = ec.generate_private_key(ec.SECP256R1())
        ec256_public = ec256_private.public_key()
        ec256_sig = ec256_private.sign(canonical, ec.ECDSA(hashes.SHA256()))
        ec256_doc = dict(base_doc)
        ec256_doc["signature"] = {
            "algorithm": "ES256",
            "key_id": "test:ec256",
            "value": base64.b64encode(ec256_sig).decode("ascii"),
        }
        ec256_pub_path = os.path.join(tmpdir, "ec256.pem")
        with open(ec256_pub_path, "wb") as handle:
            handle.write(
                ec256_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        assert tsactl_core.verify_signature(ec256_doc, ec256_pub_path) is True

        ec384_private = ec.generate_private_key(ec.SECP384R1())
        ec384_public = ec384_private.public_key()
        ec384_sig = ec384_private.sign(canonical, ec.ECDSA(hashes.SHA384()))
        ec384_doc = dict(base_doc)
        ec384_doc["signature"] = {
            "algorithm": "ES384",
            "key_id": "test:ec384",
            "value": base64.b64encode(ec384_sig).decode("ascii"),
        }
        ec384_pub_path = os.path.join(tmpdir, "ec384.pem")
        with open(ec384_pub_path, "wb") as handle:
            handle.write(
                ec384_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        assert tsactl_core.verify_signature(ec384_doc, ec384_pub_path) is True

        _, ed_pub_path = tsactl_core.generate_keys(os.path.join(tmpdir, "ed"))
        with pytest.raises(ValueError) as excinfo:
            tsactl_core.verify_signature(rsa_doc, ed_pub_path)
        assert str(excinfo.value) == "Public key is not RSA"


def test_sign_document_algorithms_and_errors():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    base_doc = {"tsa_version": "1.0.0", "id": "TSA-TEST-ALG-SIGN"}

    with tempfile.TemporaryDirectory() as tmpdir:
        rsa_priv, rsa_pub = tsactl_core.generate_keys(
            os.path.join(tmpdir, "rsa"), algorithm="RS256"
        )
        rsa_signed = tsactl_core.sign_document(base_doc, rsa_priv, "test:rsa", algorithm="RS256")
        assert tsactl_core.verify_signature(rsa_signed, rsa_pub) is True
        rsa_signed_auto = tsactl_core.sign_document(base_doc, rsa_priv, "test:rsa")
        assert rsa_signed_auto["signature"]["algorithm"] == "RS256"
        assert tsactl_core.verify_signature(rsa_signed_auto, rsa_pub) is True

        ec256_priv, ec256_pub = tsactl_core.generate_keys(
            os.path.join(tmpdir, "ec256"), algorithm="ES256"
        )
        ec256_signed = tsactl_core.sign_document(
            base_doc, ec256_priv, "test:ec256", algorithm="ES256"
        )
        assert tsactl_core.verify_signature(ec256_signed, ec256_pub) is True
        ec256_signed_auto = tsactl_core.sign_document(base_doc, ec256_priv, "test:ec256")
        assert ec256_signed_auto["signature"]["algorithm"] == "ES256"
        assert tsactl_core.verify_signature(ec256_signed_auto, ec256_pub) is True

        ec384_priv, ec384_pub = tsactl_core.generate_keys(
            os.path.join(tmpdir, "ec384"), algorithm="ES384"
        )
        ec384_signed = tsactl_core.sign_document(
            base_doc, ec384_priv, "test:ec384", algorithm="ES384"
        )
        assert tsactl_core.verify_signature(ec384_signed, ec384_pub) is True
        ec384_signed_auto = tsactl_core.sign_document(base_doc, ec384_priv, "test:ec384")
        assert ec384_signed_auto["signature"]["algorithm"] == "ES384"
        assert tsactl_core.verify_signature(ec384_signed_auto, ec384_pub) is True

        ed_priv, _ = tsactl_core.generate_keys(os.path.join(tmpdir, "ed"))
        with pytest.raises(ValueError) as excinfo:
            tsactl_core.sign_document(base_doc, ed_priv, "test:rsa", algorithm="RS256")
        assert str(excinfo.value) == "Private key is not RSA"

        with pytest.raises(ValueError) as excinfo:
            tsactl_core.sign_document(base_doc, ed_priv, "test:ec256", algorithm="ES256")
        assert str(excinfo.value) == "Private key is not P-256"

        with pytest.raises(ValueError) as excinfo:
            tsactl_core.sign_document(base_doc, ed_priv, "test:ec384", algorithm="ES384")
        assert str(excinfo.value) == "Private key is not P-384"

        with pytest.raises(ValueError) as excinfo:
            tsactl_core.sign_document(base_doc, ed_priv, "test:bad", algorithm="NOPE")
        assert str(excinfo.value) == "Unsupported algorithm: NOPE"


def test_detect_signing_algorithm_errors():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    from cryptography.hazmat.primitives.asymmetric import ec

    bad_ec_key = ec.generate_private_key(ec.SECP521R1())
    with pytest.raises(ValueError) as excinfo:
        tsactl_core._detect_signing_algorithm(bad_ec_key)
    assert str(excinfo.value) == "Unsupported EC curve for signing"

    with pytest.raises(ValueError) as excinfo:
        tsactl_core._detect_signing_algorithm(object())
    assert str(excinfo.value) == "Unsupported private key type for signing"


def test_generate_keys_invalid_algorithm():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    with pytest.raises(ValueError) as excinfo:
        tsactl_core.generate_keys("prefix", algorithm="NOPE")
    assert str(excinfo.value) == "Unsupported algorithm: NOPE"


def test_tsa_to_osv_missing_optional_sections():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-9999",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Minimal",
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    assert osv["id"] == "TSA-OSV-2025-9999"
    assert "severity" not in osv
    assert "references" not in osv
    assert "aliases" not in osv
    assert osv["database_specific"]["tsa_id"] == "TSA-2025-9999"


def test_osv_to_tsa_minimal_defaults():
    osv_doc = {
        "id": "GHSA-0000-1111-2222",
        "published": "2025-03-01T00:00:00Z",
        "summary": "Minimal OSV",
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["tsa_version"] == "1.0.0"
    assert tsa["publisher"]["name"] == "OSV Import"
    assert tsa["title"] == "Minimal OSV"
    assert tsa["affected"] == [{"tool": {"name": "unknown"}, "status": "AFFECTED"}]
    assert tsa["actions"][0]["type"] == "WARN"
    assert tsa["references"][-1]["type"] == "ADVISORY"
    assert tsa["related_vulnerabilities"][0]["id"] == "GHSA-0000-1111-2222"


def test_osv_to_tsa_ignores_introduced_zero_and_invalid_scores():
    osv_doc = {
        "id": "GHSA-1111-2222-3333",
        "published": "2025-03-01T00:00:00Z",
        "summary": "OSV",
        "severity": [{"type": "CVSS_V3", "vector": "CVSS:3.1/AV:N", "score": "n/a"}],
        "affected": [
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
        "aliases": ["NOT-A-CVE"],
        "credits": [{"name": "Alice", "type": "FINDER", "contact": []}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    entry = tsa["affected"][0]
    assert "versions" not in entry
    assert "severity" not in tsa or "score" not in tsa["severity"].get("cvss_v3", {})
    assert not any(ref.get("type") == "CVE" for ref in tsa.get("references", []))
    assert "contact" not in tsa.get("credits", [{}])[0]


def test_tsa_to_osv_affected_range_without_version():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-8888",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "publisher": {"name": "Test", "namespace": "https://example.test"},
        "title": "Range advisory",
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"affected_range": ">=dev"},
            }
        ],
        "references": [{"type": "OTHER", "url": "https://example.test/other"}],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    events = osv["affected"][0]["ranges"][0]["events"]
    assert events[0]["introduced"] == "0"
    assert osv["references"][0]["type"] == "WEB"


def test_ecosystem_to_registry_case_fallbacks():
    assert osv_converter_core._ecosystem_to_registry("PyPI") == "pypi"
    assert osv_converter_core._ecosystem_to_registry("CRATES.IO") == "crates"
    assert osv_converter_core._ecosystem_to_registry("Unknown") == "unknown"


def test_build_feed_severity_and_cve_dedupe():
    with tempfile.TemporaryDirectory() as tmpdir:
        advisory_dir = Path(tmpdir)
        doc = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-1000",
            "title": "Test",
            "modified": "2025-01-02T00:00:00Z",
            "severity": {"qualitative": "HIGH"},
            "references": [{"type": "CVE", "id": "CVE-2025-0001"}],
            "related_vulnerabilities": [{"id": "CVE-2025-0001"}],
        }
        path = advisory_dir / "TSA-TEST-1000.tsa.json"
        path.write_text(json.dumps(doc))

        feed = build_feed_core.build_feed(advisory_dir, inline=False)
        assert feed["advisories"][0]["severity"] == "HIGH"
        assert feed["advisories"][0]["cve"] == ["CVE-2025-0001"]


def test_build_feed_invalid_severity_and_missing_cve():
    with tempfile.TemporaryDirectory() as tmpdir:
        advisory_dir = Path(tmpdir)
        doc = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-1001",
            "title": "Test",
            "modified": "2025-01-03T00:00:00Z",
            "severity": {"qualitative": "UNKNOWN"},
            "references": [{"type": "WEB", "url": "https://example.test"}],
            "related_vulnerabilities": [{"id": "NOT-CVE"}],
        }
        (advisory_dir / "TSA-TEST-1001.tsa.json").write_text(json.dumps(doc))
        feed = build_feed_core.build_feed(advisory_dir, inline=False)
        entry = feed["advisories"][0]
        assert "severity" not in entry
        assert "cve" not in entry


def test_build_feed_skips_invalid_json(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        advisory_dir = Path(tmpdir)
        bad_path = advisory_dir / "bad.tsa.json"
        bad_path.write_text("{invalid-json")
        feed = build_feed_core.build_feed(advisory_dir, inline=False)
        assert feed["advisories"] == []
        captured = capsys.readouterr()
        assert "Failed to process" in captured.err


def test_registry_compare_versions_matches_tsactl():
    registry = registry_core.TSARegistry()
    cases = [
        ("1.0.0", "1.0.0"),
        ("1.0.1", "1.0.0"),
        ("1.0.0", "1.0.1"),
        ("1.0.0-alpha.1", "1.0.0"),
        ("1.0.0", "1.0.0-beta.1"),
        ("2.0.0", "10.0.0"),
        ("1.2.3", "1.2.4"),
        ("1.2.3", "1.2.3"),
    ]
    for v1, v2 in cases:
        assert registry._compare_versions(v1, v2) == tsactl_core.compare_versions(v1, v2)


def test_registry_compare_prerelease_cases():
    assert registry_core._compare_prerelease([], []) == 0
    assert registry_core._compare_prerelease([(True, 1)], [(True, 2)]) == -1
    assert registry_core._compare_prerelease([(True, 2)], [(True, 1)]) == 1
    assert registry_core._compare_prerelease([(True, 1)], [(False, "a")]) == -1
    assert registry_core._compare_prerelease([(False, "a")], [(True, 1)]) == 1
    assert registry_core._compare_prerelease([(False, "a")], [(False, "b")]) == -1
    assert registry_core._compare_prerelease([(True, 1), (False, "a")], [(True, 1)]) == 1


def test_registry_range_and_condition_matching():
    registry = registry_core.TSARegistry()
    assert registry._matches_range("1.2.3", ">=1.0.0 <2.0.0") is True
    assert registry._matches_range("2.0.0", ">=1.0.0 <2.0.0") is False
    assert registry._matches_range("1.2.3", "=1.2.3") is True
    assert registry._matches_range("1.2.3", "=1.2.4") is False
    assert registry._matches_condition("1.5.0", ">=1.0.0, <2.0.0") is True


def test_registry_version_affected_bounds():
    registry = registry_core.TSARegistry()
    affected = {"status": "AFFECTED", "versions": {"introduced": "1.0.0", "fixed": "2.0.0"}}
    assert registry._version_affected("0.9.0", affected) is False
    assert registry._version_affected("1.0.0", affected) is True
    assert registry._version_affected("1.9.9", affected) is True
    assert registry._version_affected("2.0.0", affected) is False

    affected_last = {"status": "AFFECTED", "versions": {"last_affected": "1.5.0"}}
    assert registry._version_affected("1.5.0", affected_last) is True
    assert registry._version_affected("1.5.1", affected_last) is False


def test_registry_load_trust_anchors_defaults(tmp_path):
    anchors = {
        "anchors": [
            {"key_id": "key-1", "public_key": "pk", "publisher": "pub"},
            {
                "key_id": "key-2",
                "public_key": "pk2",
                "publisher": "pub2",
                "trust_level": "warn_only",
            },
        ]
    }
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps(anchors))
    registry = registry_core.TSARegistry(trust_anchors_path=str(path))
    assert registry.trust_anchors["key-1"].trust_level == "full"
    assert registry.trust_anchors["key-2"].trust_level == "warn_only"


def test_registry_index_advisory_updates_index_and_warns(capsys):
    advisory = {
        "id": "TSA-TEST-4000",
        "actions": [{"type": "BLOCK"}],
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
        "signature": {"key_id": "unknown"},
    }
    registry = registry_core.TSARegistry(require_signatures=True)
    registry._index_advisory(advisory)
    assert "TSA-TEST-4000" in registry.advisories
    assert "demo@npm" in registry._package_index
    captured = capsys.readouterr()
    assert "Warning: Unknown signer for TSA-TEST-4000: unknown" in captured.err


def test_registry_fetch_url_file_and_local(tmp_path):
    data = {"hello": "world"}
    path = tmp_path / "data.json"
    path.write_text(json.dumps(data))
    registry = registry_core.TSARegistry()
    assert registry._fetch_url(f"file://{path}") == data
    assert registry._fetch_url(str(path)) == data


def test_registry_check_package_actions_and_signatures():
    advisory = {
        "id": "TSA-TEST-2000",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
            }
        ],
        "actions": [
            {"type": "BLOCK", "message": "Block message", "condition": ">=1.5.0 <2.0.0"},
            {"type": "WARN", "message": "Warn message"},
        ],
    }

    registry = registry_core.TSARegistry(require_signatures=False)
    registry.add_advisory(advisory)

    result_warn = registry.check_package("pkg", "1.4.0", "npm")
    assert result_warn.blocked is False
    assert "Warn message" in result_warn.warnings

    result_block = registry.check_package("pkg", "1.6.0", "npm")
    assert result_block.blocked is True
    assert result_block.message == "Block message"

    registry_signed = registry_core.TSARegistry(require_signatures=True)
    registry_signed.add_advisory(advisory)
    result_signed = registry_signed.check_package("pkg", "1.6.0", "npm")
    assert result_signed.blocked is False
    assert any("WARN instead of BLOCK" in w for w in result_signed.warnings)


def test_registry_sync_error_handling(monkeypatch):
    registry = registry_core.TSARegistry()
    registry.feeds = ["ok", "bad"]

    def fake_sync(url):
        if url == "bad":
            raise RuntimeError("boom")
        return {"added": 1, "updated": 0}

    monkeypatch.setattr(registry, "_sync_feed", fake_sync)
    stats = registry.sync()
    assert stats["feeds_synced"] == 1
    assert len(stats["errors"]) == 1
    assert registry.sync_errors == stats["errors"]
    assert registry.last_sync is not None


def test_registry_sync_feed_file_and_relative_uri():
    advisory = {
        "tsa_version": "1.0.0",
        "id": "TSA-TEST-3000",
        "title": "Inline advisory",
        "modified": "2025-01-01T00:00:00Z",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            }
        ],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        advisory_path = tmp_path / "adv.tsa.json"
        advisory_path.write_text(json.dumps(advisory))
        feed_path = tmp_path / "feed.json"
        feed_doc = {
            "advisories": [
                {
                    "id": "TSA-TEST-3000",
                    "uri": "adv.tsa.json",
                    "canonical_hash": tsactl_core.compute_canonical_hash(advisory),
                }
            ]
        }
        feed_path.write_text(json.dumps(feed_doc))

        registry = registry_core.TSARegistry()
        stats = registry._sync_feed(f"file://{feed_path}")
        assert stats["added"] == 1
        assert "TSA-TEST-3000" in registry.advisories

        stats_again = registry._sync_feed(f"file://{feed_path}")
        assert stats_again["updated"] == 1


def test_registry_fetch_url_http_headers(monkeypatch):
    registry = registry_core.TSARegistry()
    seen = {}

    def fake_urlopen(req, context=None, timeout=None):
        seen["headers"] = dict(req.header_items())
        seen["context"] = context
        seen["timeout"] = timeout

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return None

            def read(self):
                return b'{"ok": true}'

        return Response()

    monkeypatch.setattr(registry_core, "urllib", None, raising=False)
    with mock.patch("urllib.request.urlopen", fake_urlopen):
        data = registry._fetch_url("https://example.test/feed.json")

    assert data == {"ok": True}
    assert seen["headers"].get("User-agent") == "TSA-Registry-SDK/1.0.0"
    assert seen["headers"].get("Accept") == "application/json"
    assert seen["context"] is not None
    assert seen["timeout"] == 30


def test_registry_resolve_url_variants():
    registry = registry_core.TSARegistry()
    assert (
        registry._resolve_url("https://example.test/feed.json", "adv.json")
        == "https://example.test/adv.json"
    )
    assert registry._resolve_url("file:///tmp/feed.json", "adv.json") == "/tmp/adv.json"
    assert registry._resolve_url("/tmp/feed.json", "adv.json") == "/tmp/adv.json"


def test_registry_get_statistics_counts():
    registry = registry_core.TSARegistry()
    registry.feeds.append("file://example")
    registry.trust_anchors["key"] = registry_core.TrustAnchor(
        key_id="key", public_key="pk", publisher="pub"
    )
    advisory = {
        "id": "TSA-TEST-5000",
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
    }
    registry.add_advisory(advisory)
    stats = registry.get_statistics()
    assert stats["feeds_subscribed"] == 1
    assert stats["advisories_indexed"] == 1
    assert stats["packages_tracked"] == 1
    assert stats["trust_anchors"] == 1


def test_canonicalize_rejects_nan_and_infinity():
    with pytest.raises(ValueError) as excinfo:
        tsactl_core.canonicalize({"x": float("nan")})
    assert str(excinfo.value) == "NaN not allowed in canonical JSON"

    with pytest.raises(ValueError) as excinfo:
        tsactl_core.canonicalize({"x": float("inf")})
    assert str(excinfo.value) == "Infinity not allowed in canonical JSON"

    with pytest.raises(ValueError) as excinfo:
        tsactl_core.canonicalize({"x": float("-inf")})
    assert str(excinfo.value) == "Infinity not allowed in canonical JSON"


def test_canonicalize_rejects_unknown_type():
    class Custom:
        pass

    instance = Custom()
    with pytest.raises(TypeError) as excinfo:
        tsactl_core.canonicalize(instance)
    assert str(excinfo.value) == f"Cannot canonicalize type: {type(instance)}"


def test_find_schema_path_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(tsactl_core.Path, "exists", lambda self: False)
    assert tsactl_core.find_schema_path() is None


def test_validate_schema_reports_missing_jsonschema(monkeypatch):
    monkeypatch.setattr(tsactl_core, "JSONSCHEMA_AVAILABLE", False)
    errors = tsactl_core.validate_schema({"a": 1}, {"type": "object"})
    assert errors == ["jsonschema library not available - install with: pip install jsonschema"]


def test_validate_schema_enforces_format_checker():
    if not tsactl_core.JSONSCHEMA_AVAILABLE:
        pytest.skip("jsonschema not available")

    schema = {
        "type": "object",
        "properties": {"ts": {"type": "string", "format": "date-time"}},
        "required": ["ts"],
        "additionalProperties": False,
    }
    errors = tsactl_core.validate_schema({"ts": "not-a-date"}, schema)
    assert any("date-time" in e for e in errors)


def test_validate_tsa_warns_when_schema_missing(monkeypatch):
    monkeypatch.setattr(tsactl_core, "load_schema", lambda: None)
    monkeypatch.setattr(tsactl_core, "validate_semantics", lambda doc: ([], []))
    result = tsactl_core.validate_tsa({"tsa_version": "1.0.0"})
    assert result.valid is True
    assert result.warnings == [
        "Could not find schema file - skipping schema validation",
        "Ensure schema/tsa-v1.0.0.schema.json is in the package",
    ]


def test_tsactl_version_in_range_additional_operators():
    assert tsactl_core.version_in_range("v1.2.3", ">1.2.2") is True
    assert tsactl_core.version_in_range("1.2.3", ">1.2.3") is False
    assert tsactl_core.version_in_range("1.2.3", "<=1.2.3") is True
    assert tsactl_core.version_in_range("1.2.3", "<1.2.3") is False
    assert tsactl_core.version_in_range("1.2.3", ">=1.2.3 and <1.2.4") is True
    assert tsactl_core.version_in_range("1.2.3", ">=1.2.0 AND <1.3.0") is True
    assert tsactl_core.version_in_range("1.2.4", ">=1.2.3, <1.2.4") is False


def test_tsactl_compare_versions_additional_cases():
    cases = [
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha.2", -1),
        ("1.0.0-alpha.2", "1.0.0-alpha.1", 1),
        ("v1.2.3", "1.2.3", 0),
        ("1.2.3+build.1", "1.2.3+build.2", 0),
        ("1.0.0a", "1.0.0b", -1),
        ("1.2", "1.2.0", 0),
        ("1.2.0", "1.2", 0),
    ]
    for v1, v2, expected in cases:
        assert tsactl_core.compare_versions(v1, v2) == expected


def test_match_advisory_registry_and_last_affected_edges():
    tsa_doc = {
        "id": "TSA-EDGE-0001",
        "severity": {"qualitative": "LOW"},
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "pypi"},
                "status": "AFFECTED",
                "versions": {"last_affected": "2.0.0"},
            },
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"affected_range": ">=1.0.0 <2.0.0"},
            },
        ],
    }
    inventory = [
        {"name": "pkg", "version": "2.0.0", "registry": "pypi"},
        {"name": "pkg", "version": "2.0.1", "registry": "pypi"},
        {"name": "pkg", "version": "1.5.0", "registry": "npm"},
        {"name": "pkg", "version": "2.5.0", "registry": "npm"},
    ]
    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert [m["version"] for m in matches] == ["2.0.0", "1.5.0"]


def test_verify_signature_missing_or_wrong_algorithm():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        _, pub_path = tsactl_core.generate_keys(os.path.join(tmpdir, "key"))

        with pytest.raises(ValueError) as excinfo:
            tsactl_core.verify_signature({"id": "TSA-TEST-1"}, pub_path)
        assert str(excinfo.value) == "Document has no signature"

        bad_sig = {
            "id": "TSA-TEST-2",
            "signature": {"algorithm": "NOPE", "key_id": "x", "value": "AA=="},
        }
        with pytest.raises(ValueError) as excinfo:
            tsactl_core.verify_signature(bad_sig, pub_path)
        assert str(excinfo.value) == "Unsupported algorithm: NOPE"


def test_crypto_unavailable_error_messages(monkeypatch):
    monkeypatch.setattr(tsactl_core, "CRYPTO_AVAILABLE", False)
    with pytest.raises(RuntimeError) as excinfo:
        tsactl_core.generate_keys("prefix")
    assert (
        str(excinfo.value)
        == "cryptography library not available - install with: pip install cryptography"
    )

    with pytest.raises(RuntimeError) as excinfo:
        tsactl_core.sign_document({"id": "TSA-TEST"}, "missing.pem", "key")
    assert str(excinfo.value) == "cryptography library not available"

    with pytest.raises(RuntimeError) as excinfo:
        tsactl_core.verify_signature({"id": "TSA-TEST"}, "missing.pem")
    assert str(excinfo.value) == "cryptography library not available"


def test_tsa_to_osv_severity_refs_aliases_and_mcp_fields():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-0100",
        "title": "Severity map",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "severity": {
            "cvss_v4": {"vector": "CVSS:4.0/AV:N", "score": 9.8},
            "cvss_v3": {"vector": "CVSS:3.1/AV:N"},
        },
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm", "purl": "pkg:npm/demo"},
                "status": "AFFECTED",
                "versions": {"affected_range": ">=1.2.3 <2.0.0"},
                "capabilities_abused": ["filesystem"],
                "semantic_drift": "none",
            }
        ],
        "references": [
            {"type": "CVE", "id": "CVE-2025-0100", "url": "https://nvd.example/CVE"},
            {"type": "OTHER", "url": "https://example.test/other"},
        ],
        "related_vulnerabilities": [{"id": "CVE-2025-0100"}, {"id": "GHSA-XXXX"}],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    sev_by_type = {entry["type"]: entry for entry in osv["severity"]}
    assert sev_by_type["CVSS_V4"]["score"] == "9.8"
    assert "score" not in sev_by_type["CVSS_V3"]
    ref_types = [ref["type"] for ref in osv["references"]]
    assert "ADVISORY" in ref_types
    assert "WEB" in ref_types
    assert osv["aliases"] == ["CVE-2025-0100", "GHSA-XXXX"]
    db_specific = osv["affected"][0]["database_specific"]
    assert db_specific["capabilities_abused"] == ["filesystem"]
    assert db_specific["semantic_drift"] == "none"


def test_tsa_to_osv_affected_range_parsing_to_introduced():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-0101",
        "title": "Range",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {
                "tool": {"name": "demo", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"affected_range": ">=1.2.3 <2.0.0"},
            }
        ],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    events = osv["affected"][0]["ranges"][0]["events"]
    assert events[0]["introduced"] == "1.2.3"


def test_osv_to_tsa_severity_aliases_and_references():
    osv_doc = {
        "id": "OSV-2025-0001",
        "published": "2025-02-01T00:00:00Z",
        "summary": "OSV doc",
        "severity": [
            {"type": "CVSS_V4", "vector": "CVSS:4.0/AV:N", "score": "9.8"},
            {"type": "CVSS_V3", "vector": "CVSS:3.1/AV:N", "score": "oops"},
        ],
        "references": [
            {"type": "PACKAGE", "url": "https://example.test/pkg"},
            {"type": "EVIDENCE", "url": "https://example.test/evidence"},
        ],
        "aliases": ["CVE-2025-0001", "NOT-CVE"],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["severity"]["cvss_v4"]["score"] == 9.8
    assert "score" not in tsa["severity"]["cvss_v3"]
    ref_types = [ref["type"] for ref in tsa["references"]]
    assert "WEB" in ref_types
    assert "OTHER" in ref_types
    assert any(ref.get("type") == "CVE" for ref in tsa["references"])
    assert tsa["related_vulnerabilities"][0]["id"] == "OSV-2025-0001"


def test_osv_to_tsa_versions_and_database_specific_fields():
    osv_doc = {
        "id": "GHSA-9999-8888-7777",
        "published": "2025-02-02T00:00:00Z",
        "summary": "OSV with ranges",
        "affected": [
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.0.0"},
                            {"last_affected": "1.5.0"},
                        ],
                    }
                ],
                "database_specific": {
                    "capabilities_abused": ["network"],
                    "attack_context": "remote",
                },
            }
        ],
        "credits": [{"name": "Dev", "type": "REPORTER", "contact": ["dev@example.test"]}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    entry = tsa["affected"][0]
    assert entry["versions"] == {"fixed": "2.0.0", "last_affected": "1.5.0"}
    assert entry["capabilities_abused"] == ["network"]
    assert entry["attack_context"] == "remote"
    assert tsa["credits"][0]["contact"] == "dev@example.test"


def test_resolve_tsa_id_cases():
    assert osv_converter_core._resolve_tsa_id("TSA-OSV-2025-0001", None, None) == "TSA-2025-0001"
    assert osv_converter_core._resolve_tsa_id("TSA-2025-0002", None, None) == "TSA-2025-0002"
    assert osv_converter_core._resolve_tsa_id("OSV-2025-0003", None, None) == "TSA-2025-0003"
    assert (
        osv_converter_core._resolve_tsa_id("X-UNKNOWN", "TSA-TEST-2025-9999", None)
        == "TSA-TEST-2025-9999"
    )
    generated = osv_converter_core._resolve_tsa_id("X-UNKNOWN", None, "2025-01-01T00:00:00Z")
    assert generated.startswith("TSA-TEST-2025-")


def test_registry_to_ecosystem_mapping():
    assert osv_converter_core._registry_to_ecosystem("npm") == "npm"
    assert osv_converter_core._registry_to_ecosystem("PyPI") == "PyPI"
    assert osv_converter_core._registry_to_ecosystem("custom") == "custom"


def test_build_feed_inline_and_sorting_and_hash():
    with tempfile.TemporaryDirectory() as tmpdir:
        advisory_dir = Path(tmpdir)
        older = {
            "tsa_version": "1.0.0",
            "id": "TSA-OLD",
            "title": "Old",
            "modified": "2025-01-01T00:00:00Z",
        }
        newer = {
            "tsa_version": "1.0.0",
            "id": "TSA-NEW",
            "title": "New",
            "modified": "2025-02-01T00:00:00Z",
        }
        (advisory_dir / "old.tsa.json").write_text(json.dumps(older))
        (advisory_dir / "new.tsa.json").write_text(json.dumps(newer))

        feed = build_feed_core.build_feed(advisory_dir, inline=True)
        assert feed["advisories"][0]["id"] == "TSA-NEW"
        assert "advisory" in feed["advisories"][0]
        assert feed["advisories"][1]["id"] == "TSA-OLD"
        assert feed["advisories"][0]["canonical_hash"] == tsactl_core.compute_canonical_hash(newer)


def test_build_feed_base_url_overwrites_uri():
    with tempfile.TemporaryDirectory() as tmpdir:
        advisory_dir = Path(tmpdir)
        doc = {
            "tsa_version": "1.0.0",
            "id": "TSA-BASE",
            "title": "Base",
            "modified": "2025-01-01T00:00:00Z",
        }
        (advisory_dir / "base.tsa.json").write_text(json.dumps(doc))
        feed = build_feed_core.build_feed(advisory_dir, base_url="https://example.test/base")
        assert feed["advisories"][0]["uri"] == "https://example.test/base/base.tsa.json"


def test_registry_init_cache_dir_and_missing_anchors(tmp_path):
    missing = tmp_path / "missing.json"
    cache_dir = tmp_path / "cache"
    registry = registry_core.TSARegistry(
        trust_anchors_path=str(missing), cache_dir=str(cache_dir), require_signatures=True
    )
    assert registry.require_signatures is True
    assert registry.trust_anchors == {}
    assert registry.cache_dir and registry.cache_dir.exists()


def test_registry_subscribe_feed_dedup_and_sync_now(monkeypatch):
    registry = registry_core.TSARegistry()
    called = {"count": 0}

    def fake_sync():
        called["count"] += 1
        return {}

    monkeypatch.setattr(registry, "sync", fake_sync)
    registry.subscribe_feed("file://feed.json", sync_now=True)
    registry.subscribe_feed("file://feed.json", sync_now=False)
    assert registry.feeds == ["file://feed.json"]
    assert called["count"] == 1


def test_registry_sync_with_no_feeds():
    registry = registry_core.TSARegistry()
    stats = registry.sync()
    assert stats["feeds_synced"] == 0
    assert stats["errors"] == []
    assert registry.last_sync is not None


def test_registry_sync_feed_hash_mismatch_skips(capsys):
    advisory = {
        "id": "TSA-HASH-1",
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
    }
    feed_data = {
        "advisories": [{"id": "TSA-HASH-1", "advisory": advisory, "canonical_hash": "sha256:bad"}]
    }
    registry = registry_core.TSARegistry()
    with mock.patch.object(registry, "_fetch_url", return_value=feed_data):
        stats = registry._sync_feed("file://feed.json")
    assert stats["added"] == 0
    assert "TSA-HASH-1" not in registry.advisories
    captured = capsys.readouterr()
    assert "Hash mismatch" in captured.err


def test_registry_sync_feed_entry_without_advisory_or_uri(capsys):
    feed_data = {"advisories": [{"id": "TSA-NO-ADV"}]}
    registry = registry_core.TSARegistry()
    with mock.patch.object(registry, "_fetch_url", return_value=feed_data):
        stats = registry._sync_feed("file://feed.json")
    assert stats == {"added": 0, "updated": 0}
    assert registry.advisories == {}
    captured = capsys.readouterr()
    assert captured.err == ""


def test_registry_sync_feed_continues_on_entry_error():
    advisory = {
        "id": "TSA-GOOD",
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
    }
    feed_data = {
        "advisories": [
            {"id": "TSA-BAD", "url": "bad.json"},
            {"id": "TSA-GOOD", "advisory": advisory},
        ]
    }
    registry = registry_core.TSARegistry()

    def fake_fetch(url):
        if url == "feed":
            return feed_data
        raise RuntimeError("boom")

    with mock.patch.object(registry, "_fetch_url", side_effect=fake_fetch):
        stats = registry._sync_feed("feed")
    assert stats["added"] == 1
    assert "TSA-GOOD" in registry.advisories


def test_registry_index_advisory_missing_id():
    registry = registry_core.TSARegistry()
    registry._index_advisory({"affected": []})
    assert registry.advisories == {}
    assert registry._package_index == {}


def test_registry_index_advisory_unsigned_block_warns(capsys):
    advisory = {
        "id": "TSA-UNSIGNED",
        "actions": [{"type": "BLOCK"}],
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
    }
    registry = registry_core.TSARegistry(require_signatures=True)
    registry._index_advisory(advisory)
    captured = capsys.readouterr()
    assert (
        "Warning: Unsigned advisory TSA-UNSIGNED has BLOCK actions, treating as WARN only"
        in captured.err
    )
    assert "TSA-UNSIGNED" in registry.advisories


def test_registry_check_package_condition_skip_and_default_message():
    advisory = {
        "id": "TSA-DEFAULT-MSG",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            }
        ],
        "actions": [
            {"type": "BLOCK", "condition": ">=2.0.0"},
            {"type": "WARN"},
        ],
    }
    registry = registry_core.TSARegistry()
    registry.add_advisory(advisory)
    result = registry.check_package("pkg", "1.5.0", "npm")
    assert result.blocked is False
    assert any("Security issue: TSA-DEFAULT-MSG" in w for w in result.warnings)


def test_registry_version_affected_with_range_and_status():
    registry = registry_core.TSARegistry()
    affected = {"status": "AFFECTED", "versions": {"affected_range": ">=1.0.0 <2.0.0"}}
    assert registry._version_affected("1.5.0", affected) is True
    assert registry._version_affected("2.0.0", affected) is False
    assert registry._version_affected("1.5.0", {"status": "NOT_AFFECTED"}) is False


def test_registry_matches_range_more_operators():
    registry = registry_core.TSARegistry()
    assert registry._matches_range("1.2.3", ">1.2.2") is True
    assert registry._matches_range("1.2.3", ">1.2.3") is False
    assert registry._matches_range("1.2.3", "<=1.2.3") is True
    assert registry._matches_range("1.2.3", "<1.2.3") is False
    assert registry._matches_range("v1.2.3", "=1.2.3") is True
    assert registry._matches_range("1.2.4", ">=1.2.3 and <1.2.4") is False


def test_registry_compare_versions_non_semver_cases():
    registry = registry_core.TSARegistry()
    assert registry._compare_versions("1.2", "1.2.0") == 0
    assert registry._compare_versions("1.2.0", "1.2") == 0
    assert registry._compare_versions("1.2.a", "1.2.1") == 1


def test_registry_parse_semver_valid_and_invalid():
    assert registry_core._parse_semver("1.2.3-alpha.1") == (1, 2, 3, [(False, "alpha"), (True, 1)])
    assert registry_core._parse_semver("not-a-version") is None


def test_registry_get_advisory_missing():
    registry = registry_core.TSARegistry()
    assert registry.get_advisory("missing") is None


def test_registry_get_statistics_with_last_sync_and_errors():
    registry = registry_core.TSARegistry()
    registry.last_sync = datetime(2025, 1, 1)
    registry.sync_errors = ["err1", "err2"]
    stats = registry.get_statistics()
    assert stats["last_sync"].startswith("2025-01-01T")
    assert stats["sync_errors"] == 2


def test_canonicalize_nested_and_escape_sequences():
    doc = {"z": 1, "a": {"b": 2}, "s": 'quote"'}
    assert tsactl_core.canonicalize(doc) == '{"a":{"b":2},"s":"quote\\"","z":1}'

    doc = {"exp": 1e-6, "neg": -5}
    assert tsactl_core.canonicalize(doc) == '{"exp":1e-06,"neg":-5}'


def test_validate_semantics_no_warnings_when_complete():
    doc = {
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
        "references": [{"type": "CVE", "id": "CVE-2025-0001"}],
        "severity": {"cvss_v3": {"vector": "CVSS:3.1/AV:N", "score": 5.0}},
    }
    errors, warnings = tsactl_core.validate_semantics(doc)
    assert errors == []
    assert warnings == []


def test_validate_semantics_warns_without_affected_status_or_block():
    doc = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [{"status": "NOT_AFFECTED", "tool": {"name": "demo"}}],
        "actions": [{"type": "INFO"}],
        "references": [{"type": "WEB", "url": "https://example.test"}],
        "severity": {"cvss_v4": {"vector": "CVSS:4.0/AV:N", "score": 9.1}},
    }
    errors, warnings = tsactl_core.validate_semantics(doc)
    assert errors == []
    assert "No entries with AFFECTED status - is this advisory actionable?" in warnings
    assert "No BLOCK or WARN actions - registries may not enforce this advisory" in warnings


def test_validate_tsa_skips_semantics_on_schema_error(monkeypatch):
    called = {"count": 0}

    def fake_semantics(doc):
        called["count"] += 1
        return [], []

    monkeypatch.setattr(tsactl_core, "load_schema", lambda: {"type": "object"})
    monkeypatch.setattr(tsactl_core, "validate_schema", lambda doc, schema: ["boom"])
    monkeypatch.setattr(tsactl_core, "validate_semantics", fake_semantics)

    result = tsactl_core.validate_tsa({"tsa_version": "1.0.0"})
    assert result.valid is False
    assert called["count"] == 0


def test_validation_result_adders_and_summary():
    result = tsactl_core.ValidationResult()
    result.add_schema_error("schema error")
    result.add_semantic_error("semantic error")
    result.add_warning("warn")

    assert result.valid is False
    assert result.schema_errors == ["schema error"]
    assert result.semantic_errors == ["semantic error"]
    assert result.warnings == ["warn"]

    expected = (
        "✗ Validation FAILED\n\n"
        "Schema Errors (1):\n  - schema error\n\n"
        "Semantic Errors (1):\n  - semantic error\n\n"
        "Warnings (1):\n  - warn"
    )
    assert result.summary() == expected


def test_find_schema_path_prefers_script_dir(tmp_path, monkeypatch):
    schema_dir = tmp_path / "schema"
    schema_dir.mkdir(parents=True)
    schema_file = schema_dir / "tsa-v1.0.0.schema.json"
    schema_file.write_text("{}")
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    fake_file = tools_dir / "tsactl_core.py"
    fake_file.write_text("# stub")
    monkeypatch.setattr(tsactl_core, "__file__", str(fake_file))
    assert tsactl_core.find_schema_path() == schema_file.resolve()


def test_find_schema_path_falls_back_to_cwd(tmp_path, monkeypatch):
    root = tmp_path / "root"
    tools_dir = root / "tools"
    tools_dir.mkdir(parents=True)
    fake_file = tools_dir / "tsactl_core.py"
    fake_file.write_text("# stub")
    monkeypatch.setattr(tsactl_core, "__file__", str(fake_file))

    cwd = tmp_path / "cwd"
    (cwd / "schema").mkdir(parents=True)
    schema_file = cwd / "schema" / "tsa-v1.0.0.schema.json"
    schema_file.write_text("{}")
    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        assert tsactl_core.find_schema_path() == schema_file.resolve()
    finally:
        os.chdir(old_cwd)


def test_sign_document_overwrites_existing_signature():
    if not tsactl_core.CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path, pub_path = tsactl_core.generate_keys(os.path.join(tmpdir, "key"))
        doc = {
            "tsa_version": "1.0.0",
            "id": "TSA-TEST-OVERWRITE",
            "signature": {
                "algorithm": "Ed25519",
                "key_id": "old",
                "value": "AA==",
                "timestamp": "2025-01-01T00:00:00Z",
            },
        }
        signed = tsactl_core.sign_document(doc, priv_path, "new:key")
        assert signed["signature"]["key_id"] == "new:key"
        assert signed["signature"]["value"] != "AA=="
        assert tsactl_core.verify_signature(signed, pub_path) is True


def test_match_advisory_multiple_paths_and_defaults():
    tsa_doc = {
        "id": "TSA-MULTI-1",
        "affected": [
            {"tool": {"name": "alpha"}, "status": "AFFECTED", "versions": {}},
            {
                "tool": {"name": "beta", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
            },
            {
                "tool": {"name": "gamma", "registry": "pypi"},
                "status": "AFFECTED",
                "versions": {"affected_range": ">=0.5.0 <1.0.0"},
            },
        ],
    }
    inventory = [
        {"name": "alpha", "version": "0.1.0", "registry": "npm"},
        {"name": "beta", "version": "2.0.0", "registry": "npm"},
        {"name": "beta", "version": "1.0.0", "registry": "npm"},
        {"name": "gamma", "version": "0.7.0", "registry": "pypi"},
    ]
    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert [m["tool"] for m in matches] == ["alpha", "beta", "gamma"]
    assert matches[0]["severity"] == "UNKNOWN"
    assert matches[1]["fixed_version"] == "2.0.0"
    assert matches[2]["fixed_version"] == "N/A"


def test_match_advisory_defaults_registry_for_inventory():
    tsa_doc = {
        "id": "TSA-DEFAULT-REG",
        "affected": [
            {"tool": {"name": "pkg", "registry": "npm"}, "status": "AFFECTED", "versions": {}}
        ],
    }
    inventory = [{"name": "pkg", "version": "1.0.0"}]
    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert matches[0]["registry"] == "npm"


def test_match_advisory_no_affected_returns_empty():
    assert tsactl_core.match_advisory({"id": "TSA-NONE"}, [{"name": "pkg"}]) == []


def test_tsa_to_osv_full_conversion():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-1234",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "withdrawn": "2025-01-03T00:00:00Z",
        "title": "Full",
        "description": "Details",
        "severity": {
            "cvss_v4": {"vector": "CVSS:4.0/AV:N", "score": 9.9},
            "cvss_v3": {"vector": "CVSS:3.1/AV:N", "score": 7.1},
        },
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm", "purl": "pkg:npm/pkg@1.0.0"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "1.2.0", "last_affected": "1.1.9"},
                "capabilities_abused": ["network"],
                "semantic_drift": {"original": "safe", "current": "unsafe"},
                "attack_context": {"requires_agent_execution": True},
                "impact_statement": "Impact",
            }
        ],
        "references": [
            {"type": "CVE", "id": "CVE-2025-1234", "url": "https://nvd.test/CVE"},
            {"type": "ADVISORY", "url": "https://example.test/advisory"},
            {"type": "ARTICLE", "url": "https://example.test/article"},
            {"type": "FIX", "url": "https://example.test/fix"},
            {"type": "REPORT", "url": "https://example.test/report"},
            {"type": "WEB", "url": "https://example.test/web"},
            {"type": "OTHER", "url": "https://example.test/other"},
        ],
        "related_vulnerabilities": [{"id": "CVE-2025-1234"}, {"id": "GHSA-XXXX"}],
        "credits": [{"name": "Alice", "type": "FINDER", "contact": "alice@example.test"}],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    expected = {
        "schema_version": "1.6.0",
        "id": "TSA-OSV-2025-1234",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "withdrawn": "2025-01-03T00:00:00Z",
        "summary": "Full",
        "details": "Details",
        "severity": [
            {"type": "CVSS_V4", "vector": "CVSS:4.0/AV:N", "score": "9.9"},
            {"type": "CVSS_V3", "vector": "CVSS:3.1/AV:N", "score": "7.1"},
        ],
        "affected": [
            {
                "package": {"name": "pkg", "ecosystem": "npm", "purl": "pkg:npm/pkg@1.0.0"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
                ],
                "database_specific": {
                    "capabilities_abused": ["network"],
                    "semantic_drift": {"original": "safe", "current": "unsafe"},
                    "attack_context": {"requires_agent_execution": True},
                    "impact_statement": "Impact",
                },
            }
        ],
        "references": [
            {"url": "https://nvd.test/CVE", "type": "ADVISORY"},
            {"url": "https://example.test/advisory", "type": "ADVISORY"},
            {"url": "https://example.test/article", "type": "ARTICLE"},
            {"url": "https://example.test/fix", "type": "FIX"},
            {"url": "https://example.test/report", "type": "REPORT"},
            {"url": "https://example.test/web", "type": "WEB"},
            {"url": "https://example.test/other", "type": "WEB"},
        ],
        "aliases": ["CVE-2025-1234", "GHSA-XXXX"],
        "credits": [{"name": "Alice", "type": "FINDER", "contact": ["alice@example.test"]}],
        "database_specific": {"tsa_id": "TSA-2025-1234", "tsa_version": "1.0.0"},
    }
    assert osv == expected


def test_osv_to_tsa_full_conversion():
    osv_doc = {
        "id": "TSA-OSV-2025-9999",
        "published": "2025-02-01T00:00:00Z",
        "modified": "2025-02-02T00:00:00Z",
        "withdrawn": "2025-02-03T00:00:00Z",
        "summary": "Summary",
        "details": "Details",
        "severity": [
            {"type": "CVSS_V4", "vector": "CVSS:4.0/AV:N", "score": "9.8"},
            {"type": "CVSS_V3", "vector": "CVSS:3.1/AV:N", "score": "7.5"},
        ],
        "affected": [
            {
                "package": {"name": "pkg", "ecosystem": "PyPI", "purl": "pkg:pypi/pkg@1.0.0"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.2.0"},
                            {"last_affected": "1.1.0"},
                        ],
                    }
                ],
                "database_specific": {
                    "capabilities_abused": ["fs"],
                    "semantic_drift": "drift",
                    "attack_context": "ctx",
                    "impact_statement": "Impact",
                },
            }
        ],
        "references": [
            {"type": "ARTICLE", "url": "https://example.test/article"},
            {"type": "EVIDENCE", "url": "https://example.test/evidence"},
        ],
        "aliases": ["CVE-2025-9999", "GHSA-YYYY"],
        "credits": [{"name": "Bob", "type": "REPORTER", "contact": ["bob@example.test"]}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    expected = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-9999",
        "published": "2025-02-01T00:00:00Z",
        "modified": "2025-02-02T00:00:00Z",
        "withdrawn": "2025-02-03T00:00:00Z",
        "publisher": {"name": "OSV Import", "namespace": "https://osv.dev"},
        "title": "Summary",
        "description": "Details",
        "severity": {
            "cvss_v4": {"vector": "CVSS:4.0/AV:N", "score": 9.8},
            "cvss_v3": {"vector": "CVSS:3.1/AV:N", "score": 7.5},
        },
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "pypi", "purl": "pkg:pypi/pkg@1.0.0"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "1.2.0", "last_affected": "1.1.0"},
                "capabilities_abused": ["fs"],
                "semantic_drift": "drift",
                "attack_context": "ctx",
                "impact_statement": "Impact",
            }
        ],
        "references": [
            {"type": "ARTICLE", "url": "https://example.test/article"},
            {"type": "OTHER", "url": "https://example.test/evidence"},
            {
                "type": "ADVISORY",
                "id": "TSA-OSV-2025-9999",
                "url": "https://osv.dev/vulnerability/TSA-OSV-2025-9999",
            },
            {
                "type": "CVE",
                "id": "CVE-2025-9999",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-9999",
            },
        ],
        "related_vulnerabilities": [{"id": "TSA-OSV-2025-9999"}],
        "actions": [
            {
                "type": "WARN",
                "urgency": "HIGH",
                "message": "Security vulnerability imported from OSV: TSA-OSV-2025-9999",
            }
        ],
        "credits": [{"name": "Bob", "type": "REPORTER", "contact": "bob@example.test"}],
    }
    assert tsa == expected


def test_tsa_to_osv_missing_id_defaults():
    tsa_doc = {"tsa_version": "1.0.0", "title": "No ID"}
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    assert osv["id"] == ""
    assert osv["database_specific"]["tsa_id"] is None


def test_osv_to_tsa_modified_defaults_to_published():
    osv_doc = {"id": "OSV-2025-0001", "published": "2025-01-01T00:00:00Z", "summary": "Sum"}
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["modified"] == "2025-01-01T00:00:00Z"


def test_osv_to_tsa_summary_default_title():
    osv_doc = {"id": "OSV-2025-0002", "published": "2025-01-01T00:00:00Z"}
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["title"] == "Imported from OSV"


def test_osv_to_tsa_severity_vector_default():
    osv_doc = {
        "id": "OSV-2025-0003",
        "published": "2025-01-01T00:00:00Z",
        "summary": "OSV",
        "severity": [{"type": "CVSS_V4"}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["severity"]["cvss_v4"]["vector"] == ""


def test_osv_to_tsa_missing_id_generates_from_published():
    osv_doc = {"published": "2025-01-01T00:00:00Z", "summary": "S"}
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["id"].startswith("TSA-TEST-2025-")


def test_osv_to_tsa_missing_published_uses_current_year_and_timestamp():
    osv_doc = {"summary": "S"}
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    current_year = datetime.utcnow().year
    assert tsa["id"].startswith(f"TSA-TEST-{current_year}-")
    assert tsa["modified"].endswith("Z")


def test_tsa_to_osv_summary_default_when_title_missing():
    tsa_doc = {"tsa_version": "1.0.0"}
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    assert osv["summary"] == ""


def test_tsa_to_osv_missing_tool_defaults():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "affected": [{"status": "AFFECTED", "versions": {}}],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    pkg = osv["affected"][0]["package"]
    assert pkg["name"] == ""
    assert pkg["ecosystem"] == "npm"


def test_mapping_case_variants_and_defaults():
    assert osv_converter_core._ecosystem_to_registry("NuGet") == "nuget"
    assert osv_converter_core._ecosystem_to_registry("RUBYGEMS") == "rubygems"
    assert osv_converter_core._registry_to_ecosystem("PYPI") == "PyPI"
    assert osv_converter_core._registry_to_ecosystem("CrAtEs") == "crates.io"
    assert osv_converter_core._ref_type_to_osv("unknown") == "WEB"
    assert osv_converter_core._osv_ref_type_to_tsa("package") == "OTHER"
    assert osv_converter_core._credit_type_to_osv("unknown") == "OTHER"


def test_generate_tsa_id_deterministic():
    osv_id = "OSV-TEST-1234"
    published = "2024-05-01T00:00:00Z"
    digest = zlib.crc32(osv_id.encode("utf-8")) % 10000
    expected = f"TSA-TEST-2024-{digest:04d}"
    assert osv_converter_core._generate_tsa_id(osv_id, published) == expected


def test_build_feed_inline_base_url_precedence(tmp_path):
    doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-INLINE",
        "title": "Inline",
        "modified": "2025-01-01T00:00:00Z",
    }
    path = tmp_path / "inline.tsa.json"
    path.write_text(json.dumps(doc))
    feed = build_feed_core.build_feed(tmp_path, base_url="https://example.test/base/", inline=True)
    assert feed["advisories"][0]["uri"] == "inline.tsa.json"
    assert feed["advisories"][0]["advisory"]["id"] == "TSA-INLINE"


def test_load_advisory_reads_json(tmp_path):
    path = tmp_path / "adv.json"
    payload = {"id": "TSA-LOAD"}
    path.write_text(json.dumps(payload))
    assert build_feed_core.load_advisory(path) == payload


def test_build_feed_handles_missing_modified(tmp_path):
    doc = {"tsa_version": "1.0.0", "id": "TSA-NOMOD", "title": "NoMod"}
    path = tmp_path / "nomod.tsa.json"
    path.write_text(json.dumps(doc))
    feed = build_feed_core.build_feed(tmp_path, inline=False)
    assert feed["advisories"][0]["modified"] is None


def test_registry_sync_accumulates_stats(monkeypatch):
    registry = registry_core.TSARegistry()
    registry.feeds = ["a", "b"]
    monkeypatch.setattr(registry, "_sync_feed", lambda url: {"added": 1, "updated": 2})
    stats = registry.sync()
    assert stats["feeds_synced"] == 2
    assert stats["advisories_added"] == 2
    assert stats["advisories_updated"] == 4
    assert stats["errors"] == []


def test_registry_sync_feed_uses_url_field(monkeypatch):
    advisory = {
        "id": "TSA-URL-1",
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
    }
    feed_data = {"advisories": [{"id": "TSA-URL-1", "url": "adv.json"}]}

    registry = registry_core.TSARegistry()

    def fake_fetch(url):
        if url == "feed":
            return feed_data
        return advisory

    monkeypatch.setattr(registry, "_fetch_url", fake_fetch)
    stats = registry._sync_feed("feed")
    assert stats["added"] == 1
    assert "TSA-URL-1" in registry.advisories


def test_registry_index_advisory_defaults_registry_and_skips_missing_name():
    advisory = {
        "id": "TSA-INDEX-1",
        "affected": [
            {"tool": {"name": "demo"}, "status": "AFFECTED"},
            {"tool": {"registry": "npm"}, "status": "AFFECTED"},
        ],
    }
    registry = registry_core.TSARegistry()
    registry._index_advisory(advisory)
    assert "demo@npm" in registry._package_index
    assert len(registry._package_index) == 1


def test_registry_check_package_signed_block(capsys, tmp_path):
    advisory = {
        "id": "TSA-SIGNED-1",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            }
        ],
        "actions": [{"type": "BLOCK", "message": "Block signed"}],
    }
    priv_path, pub_path = tsactl_core.generate_keys(str(tmp_path / "sig"))
    with open(pub_path, "r") as f:
        pub_pem = f.read()
    signed = tsactl_core.sign_document(advisory, priv_path, "key-1")
    registry = registry_core.TSARegistry(require_signatures=True)
    registry.trust_anchors["key-1"] = registry_core.TrustAnchor(
        key_id="key-1", public_key=pub_pem, publisher="pub"
    )
    registry.add_advisory(signed)
    captured = capsys.readouterr()
    assert "Warning" not in captured.err
    result = registry.check_package("pkg", "1.0.0", "npm")
    assert result.blocked is True
    assert result.message == "Block signed"


def test_registry_check_package_unknown_action_ignored():
    advisory = {
        "id": "TSA-IGNORE-1",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            }
        ],
        "actions": [{"type": "INFO"}],
    }
    registry = registry_core.TSARegistry()
    registry.add_advisory(advisory)
    result = registry.check_package("pkg", "1.0.0", "npm")
    assert result.blocked is False
    assert result.warnings == []


def test_registry_check_package_missing_advisory_id():
    registry = registry_core.TSARegistry()
    registry._package_index["pkg@npm"] = {"MISSING"}
    result = registry.check_package("pkg", "1.0.0", "npm")
    assert result.advisories == []


def test_registry_check_package_default_registry():
    advisory = {
        "id": "TSA-DEFAULT-REGISTRY",
        "affected": [
            {"tool": {"name": "pkg"}, "status": "AFFECTED", "versions": {"introduced": "1.0.0"}}
        ],
        "actions": [{"type": "WARN", "message": "Warn"}],
    }
    registry = registry_core.TSARegistry()
    registry.add_advisory(advisory)
    result = registry.check_package("pkg", "1.0.0")
    assert result.warnings == ["Warn"]


def test_registry_sync_feed_missing_advisories_key(monkeypatch):
    registry = registry_core.TSARegistry()
    monkeypatch.setattr(registry, "_fetch_url", lambda url: {})
    stats = registry._sync_feed("feed")
    assert stats == {"added": 0, "updated": 0}


def test_registry_sync_feed_handles_missing_actions_key(capsys):
    advisory = {
        "id": "TSA-ACTIONS-1",
        "affected": [{"tool": {"name": "demo"}, "status": "AFFECTED"}],
    }
    registry = registry_core.TSARegistry(require_signatures=True)
    registry._index_advisory(advisory)
    captured = capsys.readouterr()
    assert "Unsigned advisory" not in captured.err


def test_registry_sync_defaults_when_feed_stats_missing(monkeypatch):
    registry = registry_core.TSARegistry()
    registry.feeds = ["a"]
    monkeypatch.setattr(registry, "_sync_feed", lambda url: {})
    stats = registry.sync()
    assert stats["advisories_added"] == 0
    assert stats["advisories_updated"] == 0
    assert stats["feeds_synced"] == 1
    assert stats["errors"] == []


def test_registry_matches_range_case_insensitive_and_upper_bound():
    registry = registry_core.TSARegistry()
    assert registry._matches_range("1.2.3", ">=1.2.0 AND <=1.2.3") is True
    assert registry._matches_range("1.2.4", "<=1.2.3") is False


def test_registry_compare_prerelease_equal_identifiers():
    assert registry_core._compare_prerelease([(True, 1), (True, 1)], [(True, 1), (True, 2)]) == -1
    assert (
        registry_core._compare_prerelease(
            [(False, "alpha"), (True, 1)], [(False, "alpha"), (True, 2)]
        )
        == -1
    )


def test_registry_init_defaults_and_nested_cache_dir(tmp_path):
    nested = tmp_path / "a" / "b" / "c"
    registry = registry_core.TSARegistry(cache_dir=str(nested))
    assert registry.last_sync is None
    assert registry.sync_errors == []
    assert registry.cache_dir and registry.cache_dir.exists()


def test_registry_fetch_url_http_headers_http(monkeypatch):
    registry = registry_core.TSARegistry()
    seen = {}

    def fake_urlopen(req, context=None, timeout=None):
        seen["headers"] = dict(req.header_items())

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return None

            def read(self):
                return b'{"ok": true}'

        return Response()

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        data = registry._fetch_url("http://example.test/feed.json")

    assert data == {"ok": True}
    assert seen["headers"].get("User-agent") == "TSA-Registry-SDK/1.0.0"


def test_registry_load_trust_anchors_fields(tmp_path):
    anchors = {
        "anchors": [
            {"key_id": "key-1", "public_key": "pk", "publisher": "pub", "trust_level": "full"}
        ]
    }
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps(anchors))
    registry = registry_core.TSARegistry(trust_anchors_path=str(path))
    anchor = registry.trust_anchors["key-1"]
    assert anchor.public_key == "pk"
    assert anchor.publisher == "pub"


def test_validation_result_summary_passed_with_warning():
    result = tsactl_core.ValidationResult()
    result.add_warning("note")
    assert result.summary() == "✓ Validation PASSED\n\nWarnings (1):\n  - note"


def test_validate_tsa_preserves_semantic_messages(monkeypatch):
    monkeypatch.setattr(tsactl_core, "load_schema", lambda: None)
    monkeypatch.setattr(
        tsactl_core,
        "validate_semantics",
        lambda doc: (["sem error"], ["sem warn"]),
    )
    result = tsactl_core.validate_tsa({"tsa_version": "1.0.0"})
    assert result.semantic_errors == ["sem error"]
    assert "sem warn" in result.warnings


def test_validate_schema_root_path_message():
    if not tsactl_core.JSONSCHEMA_AVAILABLE:
        pytest.skip("jsonschema not available")

    schema = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "required": ["a"],
        "additionalProperties": False,
    }
    errors = tsactl_core.validate_schema({}, schema)
    assert any(err.startswith("[(root)]") for err in errors)


def test_validate_schema_nested_path_message():
    if not tsactl_core.JSONSCHEMA_AVAILABLE:
        pytest.skip("jsonschema not available")

    schema = {
        "type": "object",
        "properties": {
            "a": {
                "type": "object",
                "properties": {"b": {"type": "integer"}},
                "required": ["b"],
                "additionalProperties": False,
            }
        },
        "required": ["a"],
        "additionalProperties": False,
    }
    errors = tsactl_core.validate_schema({"a": {"b": "x"}}, schema)
    assert any(err.startswith("[a -> b]") for err in errors)


def test_find_schema_path_candidate_fallbacks(monkeypatch):
    script_dir = Path(tsactl_core.__file__).parent.resolve()
    candidates = [
        script_dir.parent / "schema" / "tsa-v1.0.0.schema.json",
        script_dir / ".." / "schema" / "tsa-v1.0.0.schema.json",
        Path("schema") / "tsa-v1.0.0.schema.json",
        Path("tsa-v1.0.0.schema.json"),
    ]
    expected = [c if c.is_absolute() else c.resolve() for c in candidates]
    for target in expected:
        monkeypatch.setattr(tsactl_core.Path, "exists", lambda self, target=target: self == target)
        assert tsactl_core.find_schema_path() == target


def test_validate_semantics_clean_doc():
    doc = {
        "tsa_version": "1.0.0",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            }
        ],
        "actions": [{"type": "BLOCK", "message": "Block it"}],
        "references": [{"type": "CVE", "id": "CVE-2025-0001"}],
        "severity": {"cvss_v3": {"vector": "CVSS:3.1/AV:N", "score": 5.0}},
    }
    errors, warnings = tsactl_core.validate_semantics(doc)
    assert errors == []
    assert warnings == []


def test_normalize_version_strips_v_prefix_case_insensitive():
    assert tsactl_core._normalize_version(" v1.2.3 ") == "1.2.3"
    assert tsactl_core._normalize_version("V1.2.3") == "1.2.3"


def test_parse_semver_prerelease_parsing():
    parsed = tsactl_core._parse_semver("1.2.3-alpha.1")
    assert parsed is not None
    assert parsed[3] == [(False, "alpha"), (True, 1)]
    parsed_num = tsactl_core._parse_semver("1.2.3-1")
    assert parsed_num is not None
    assert parsed_num[3] == [(True, 1)]


def test_compare_prerelease_lengths_and_equal():
    assert tsactl_core._compare_prerelease([(True, 1)], [(True, 1), (True, 2)]) == -1
    assert tsactl_core._compare_prerelease([(True, 1), (True, 2)], [(True, 1)]) == 1
    assert tsactl_core._compare_prerelease([(False, "a")], [(False, "a")]) == 0


def test_parse_version_tuple():
    assert tsactl_core.parse_version("1.2.3-alpha") == ((0, 1), (0, 2), (0, 3), (1, "alpha"))


def test_compare_versions_fallback_greater():
    assert tsactl_core.compare_versions("1.0.0b", "1.0.0a") == 1


def test_version_in_range_ignores_empty_parts():
    assert tsactl_core.version_in_range("1.2.3", ">=1.0.0  <2.0.0") is True


def test_version_in_range_empty_part_requires_continue(monkeypatch):
    class _RangeStub:
        def replace(self, *_args, **_kwargs):
            return self

        def split(self):
            return ["", "<=0.9.0"]

    monkeypatch.setattr(tsactl_core.re, "sub", lambda *_args, **_kwargs: _RangeStub())
    assert tsactl_core.version_in_range("1.0.0", ">=1.0.0") is False


def test_canonicalize_scientific_notation_preserved():
    assert tsactl_core.canonicalize({"exp": 1.23e20}) == '{"exp":123000000000000000000}'


def test_match_advisory_defaults_for_missing_versions_and_severity():
    tsa_doc = {
        "id": "TSA-DEFAULTS",
        "affected": [{"tool": {"name": "pkg", "registry": "npm"}, "status": "AFFECTED"}],
    }
    inventory = [{"name": "pkg", "version": "1.0.0", "registry": "npm"}]
    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert len(matches) == 1
    match = matches[0]
    assert match["severity"] == "UNKNOWN"
    assert match["impact"] == ""
    assert match["fixed_version"] == "N/A"


def test_match_advisory_continues_on_mismatch_and_status():
    tsa_doc = {
        "id": "TSA-MULTI",
        "affected": [
            {"status": "AFFECTED", "versions": {"introduced": "1.0.0"}},
            {
                "tool": {"name": "other", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            },
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "NOT_AFFECTED",
                "versions": {"introduced": "1.0.0"},
            },
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
            },
        ],
    }
    inventory = [{"name": "pkg", "version": "1.5.0", "registry": "npm"}]
    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert len(matches) == 1
    assert matches[0]["advisory_id"] == "TSA-MULTI"


def test_match_advisory_inventory_missing_version_no_match():
    tsa_doc = {
        "id": "TSA-NO-VERSION",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"affected_range": "=1.2.3"},
            }
        ],
    }
    matches = tsactl_core.match_advisory(tsa_doc, [{"name": "pkg", "registry": "npm"}])
    assert matches == []


def test_match_advisory_respects_bounds_for_out_of_range():
    tsa_doc = {
        "id": "TSA-BOUNDS",
        "affected": [
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0", "fixed": "2.0.0"},
            }
        ],
    }
    inventory = [
        {"name": "pkg", "version": "0.9.0", "registry": "npm"},
        {"name": "pkg", "version": "2.0.0", "registry": "npm"},
    ]
    matches = tsactl_core.match_advisory(tsa_doc, inventory)
    assert matches == []


def test_sign_document_signature_fields_with_stub(monkeypatch, tmp_path):
    class FakeKey:
        def sign(self, data):
            return b"sig"

    class FakeSerialization:
        def load_pem_private_key(self, data, password=None):
            return FakeKey()

    monkeypatch.setattr(tsactl_core, "CRYPTO_AVAILABLE", True)
    monkeypatch.setattr(tsactl_core, "serialization", FakeSerialization())
    monkeypatch.setattr(tsactl_core, "Ed25519PrivateKey", FakeKey)

    key_path = tmp_path / "key.pem"
    key_path.write_bytes(b"key")
    signed = tsactl_core.sign_document({"id": "TSA-TEST"}, str(key_path), "key-1")
    signature = signed["signature"]
    assert signature["algorithm"] == "Ed25519"
    assert signature["key_id"] == "key-1"
    assert signature["value"] == base64.b64encode(b"sig").decode("ascii")
    assert signature["timestamp"].endswith("Z")


def test_registry_to_ecosystem_uppercase_normalizes():
    assert osv_converter_core._registry_to_ecosystem("NPM") == "npm"


def test_osv_to_tsa_missing_id_uses_zero_serial_and_unknown_message():
    osv_doc = {"published": "2025-01-01T00:00:00Z"}
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["id"] == "TSA-TEST-2025-0000"
    assert tsa["title"] == "Imported from OSV"
    assert tsa["actions"][0]["message"].endswith("unknown")


def test_osv_to_tsa_tsa_id_override():
    osv_doc = {"id": "OSV-2025-0001", "published": "2025-01-01T00:00:00Z"}
    tsa = osv_converter_core.osv_to_tsa(osv_doc, tsa_id="TSA-OVERRIDE")
    assert tsa["id"] == "TSA-OVERRIDE"


def test_osv_to_tsa_reference_defaults():
    osv_doc = {
        "id": "OSV-REF",
        "published": "2025-01-01T00:00:00Z",
        "summary": "Ref test",
        "references": [{}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    ref = tsa["references"][0]
    assert ref["type"] == "WEB"
    assert ref["url"] == ""


def test_osv_to_tsa_missing_package_fields_defaults():
    osv_doc = {
        "id": "OSV-PKG",
        "published": "2025-01-01T00:00:00Z",
        "summary": "Pkg test",
        "affected": [{}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    entry = tsa["affected"][0]
    assert entry["tool"]["name"] == ""
    assert entry["tool"]["registry"] == ""


def test_osv_to_tsa_handles_missing_ranges_and_events():
    osv_doc = {
        "id": "OSV-RANGES",
        "published": "2025-01-01T00:00:00Z",
        "summary": "Ranges test",
        "affected": [
            {"package": {"name": "demo", "ecosystem": "npm"}},
            {"package": {"name": "demo", "ecosystem": "npm"}, "ranges": [{}]},
        ],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert "versions" not in tsa["affected"][0]
    assert "versions" not in tsa["affected"][1]


def test_osv_to_tsa_severity_missing_vector_defaults():
    osv_doc = {
        "id": "OSV-SEV",
        "published": "2025-01-01T00:00:00Z",
        "summary": "Severity test",
        "severity": [{"type": "CVSS_V3"}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    assert tsa["severity"]["cvss_v3"]["vector"] == ""


def test_osv_to_tsa_credit_defaults_and_contact_first_item():
    osv_doc = {
        "id": "OSV-CREDITS",
        "published": "2025-01-01T00:00:00Z",
        "summary": "Credits test",
        "credits": [{"type": "REPORTER", "contact": ["dev@example.test"]}],
    }
    tsa = osv_converter_core.osv_to_tsa(osv_doc)
    credit = tsa["credits"][0]
    assert credit["name"] == ""
    assert credit["type"] == "REPORTER"
    assert credit["contact"] == "dev@example.test"


def test_tsa_to_osv_missing_versions_and_registry_mapping():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-NOVERS",
        "title": "No versions",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "affected": [{"tool": {"name": "demo", "registry": "pypi"}, "status": "AFFECTED"}],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    affected = osv["affected"][0]
    assert affected["package"]["ecosystem"] == "PyPI"
    assert affected["ranges"][0]["events"][0]["introduced"] == "0"


def test_tsa_to_osv_reference_defaults_and_aliases():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-REFS",
        "title": "Refs",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "references": [
            {"type": "ARTICLE", "id": "NOT-CVE", "url": "https://example.test/article"},
            {},
        ],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    assert "aliases" not in osv
    assert osv["references"][1]["type"] == "WEB"
    assert osv["references"][1]["url"] == ""


def test_tsa_to_osv_credit_defaults():
    tsa_doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-CREDITS",
        "title": "Credits",
        "published": "2025-01-01T00:00:00Z",
        "modified": "2025-01-02T00:00:00Z",
        "credits": [{"contact": "person@example.test"}],
    }
    osv = osv_converter_core.tsa_to_osv(tsa_doc)
    credit = osv["credits"][0]
    assert credit["name"] == ""
    assert credit["type"] == "OTHER"
    assert credit["contact"] == ["person@example.test"]


def test_build_feed_severity_levels(tmp_path):
    severities = ["MEDIUM", "LOW", "INFORMATIONAL"]
    for idx, severity in enumerate(severities, start=1):
        doc = {
            "tsa_version": "1.0.0",
            "id": f"TSA-SEV-{severity}",
            "title": "Severity test",
            "modified": f"2025-01-0{idx}T00:00:00Z",
            "severity": {"qualitative": severity},
        }
        (tmp_path / f"{severity.lower()}.tsa.json").write_text(json.dumps(doc))
    feed = build_feed_core.build_feed(tmp_path, inline=False)
    by_id = {entry["id"]: entry for entry in feed["advisories"]}
    for severity in severities:
        entry = by_id[f"TSA-SEV-{severity}"]
        assert entry["severity"] == severity


def test_build_feed_related_vulnerabilities_cve(tmp_path):
    doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-REL-1",
        "title": "Rel",
        "modified": "2025-01-01T00:00:00Z",
        "related_vulnerabilities": [{"id": "CVE-2025-1234"}, {"id": "NOT-CVE"}],
    }
    path = tmp_path / "rel.tsa.json"
    path.write_text(json.dumps(doc))
    feed = build_feed_core.build_feed(tmp_path, inline=False)
    entry = feed["advisories"][0]
    assert entry["cve"] == ["CVE-2025-1234"]


def test_build_feed_base_url_trailing_slash(tmp_path):
    doc = {
        "tsa_version": "1.0.0",
        "id": "TSA-TRAIL",
        "title": "Trail",
        "modified": "2025-01-01T00:00:00Z",
    }
    path = tmp_path / "trail.tsa.json"
    path.write_text(json.dumps(doc))
    feed = build_feed_core.build_feed(tmp_path, base_url="https://example.test/base/")
    assert feed["advisories"][0]["uri"] == "https://example.test/base/trail.tsa.json"


def test_registry_init_existing_cache_dir(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    registry = registry_core.TSARegistry(cache_dir=str(cache_dir))
    assert registry.cache_dir and registry.cache_dir.exists()


def test_registry_load_trust_anchors_missing_fields(tmp_path):
    anchors = {"anchors": [{"key_id": "key-1"}]}
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps(anchors))
    registry = registry_core.TSARegistry(trust_anchors_path=str(path))
    anchor = registry.trust_anchors["key-1"]
    assert anchor.public_key == ""
    assert anchor.publisher == ""
    assert anchor.trust_level == "full"


def test_registry_load_trust_anchors_missing_key(tmp_path):
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps({}))
    registry = registry_core.TSARegistry(trust_anchors_path=str(path))
    assert registry.trust_anchors == {}


def test_registry_index_advisory_preserves_registry():
    advisory = {
        "id": "TSA-INDEX-REG",
        "affected": [{"tool": {"name": "demo", "registry": "pypi"}, "status": "AFFECTED"}],
    }
    registry = registry_core.TSARegistry()
    registry._index_advisory(advisory)
    assert "demo@pypi" in registry._package_index


def test_registry_index_advisory_handles_missing_tool():
    advisory = {
        "id": "TSA-NO-TOOL",
        "affected": [{"status": "AFFECTED"}],
    }
    registry = registry_core.TSARegistry()
    registry._index_advisory(advisory)
    assert registry._package_index == {}


def test_registry_matches_range_commas_and_empty_parts():
    registry = registry_core.TSARegistry()
    assert registry._matches_range("1.2.3", ">=1.0.0,  <2.0.0") is True
    assert registry._matches_range("1.0.0", ">=1.0.0 <2.0.0") is True


def test_registry_matches_range_empty_part_requires_continue(monkeypatch):
    class _RangeStub:
        def replace(self, *_args, **_kwargs):
            return self

        def split(self):
            return ["", "<=0.9.0"]

    registry = registry_core.TSARegistry()
    monkeypatch.setattr(registry_core.re, "sub", lambda *_args, **_kwargs: _RangeStub())
    assert registry._matches_range("1.0.0", ">=1.0.0") is False


def test_registry_matches_condition_uppercase_and():
    registry = registry_core.TSARegistry()
    assert registry._matches_condition("1.5.0", ">=1.0.0 AND <2.0.0") is True


def test_registry_compare_versions_fallback_cases():
    registry = registry_core.TSARegistry()
    assert registry._compare_versions("1.0.0a", "1.0.0b") == -1
    assert registry._compare_versions("1.0.0b", "1.0.0a") == 1


def test_registry_compare_prerelease_lengths_and_equal():
    assert registry_core._compare_prerelease([(True, 1)], [(True, 1), (True, 2)]) == -1
    assert registry_core._compare_prerelease([(True, 1), (True, 2)], [(True, 1)]) == 1
    assert registry_core._compare_prerelease([(False, "a")], [(False, "a")]) == 0


def test_registry_version_affected_missing_versions_defaults():
    registry = registry_core.TSARegistry()
    affected = {"status": "AFFECTED"}
    assert registry._version_affected("1.0.0", affected) is True


def test_registry_check_package_skips_missing_advisory_and_continues():
    advisory = {
        "id": "TSA-PRESENT",
        "affected": [
            {"tool": {"name": "pkg", "registry": "npm"}, "status": "AFFECTED"},
        ],
        "actions": [{"type": "WARN", "message": "Warn"}],
    }
    registry = registry_core.TSARegistry()
    registry.advisories["TSA-PRESENT"] = advisory
    registry._package_index["pkg@npm"] = ["MISSING", "TSA-PRESENT"]
    result = registry.check_package("pkg", "1.0.0", "npm")
    assert any(a.get("id") == "TSA-PRESENT" for a in result.advisories)


def test_registry_check_package_continues_on_mismatch_and_unaffected():
    advisory = {
        "id": "TSA-MULTI",
        "affected": [
            {"tool": {"name": "other", "registry": "npm"}, "status": "AFFECTED"},
            {"tool": {"name": "pkg", "registry": "pypi"}, "status": "AFFECTED"},
            {
                "tool": {"name": "pkg", "registry": "npm"},
                "status": "AFFECTED",
                "versions": {"introduced": "1.0.0"},
            },
            {"tool": {"name": "pkg", "registry": "npm"}, "status": "AFFECTED"},
        ],
        "actions": [{"type": "WARN", "message": "Warn"}],
    }
    registry = registry_core.TSARegistry()
    registry.add_advisory(advisory)
    result = registry.check_package("pkg", "0.8.0", "npm")
    assert result.warnings == ["Warn"]
    assert all(isinstance(action, dict) for action in result.actions)
    assert all(isinstance(adv, dict) for adv in result.advisories)


def test_registry_check_package_warn_and_block_unsigned():
    advisory = {
        "id": "TSA-UNSIGNED",
        "affected": [
            {"tool": {"name": "pkg", "registry": "npm"}, "status": "AFFECTED"},
        ],
        "actions": [
            {"type": "BLOCK", "message": "Block"},
            {"type": "WARN", "message": "Warn"},
        ],
    }
    registry = registry_core.TSARegistry(require_signatures=True)
    registry.add_advisory(advisory)
    result = registry.check_package("pkg", "1.0.0", "npm")
    assert any("WARN instead of BLOCK" in w for w in result.warnings)
    assert "Warn" in result.warnings
    assert len(result.actions) == 2


def test_registry_check_package_handles_missing_actions_and_affected():
    registry = registry_core.TSARegistry()
    registry.add_advisory(
        {
            "id": "TSA-NO-ACTIONS",
            "affected": [{"tool": {"name": "pkg", "registry": "npm"}, "status": "AFFECTED"}],
        }
    )
    registry.add_advisory({"id": "TSA-NO-AFFECTED"})
    result = registry.check_package("pkg", "1.0.0", "npm")
    assert result.actions == []
    assert all(isinstance(adv, dict) for adv in result.advisories)
