# Tool Security Advisory (TSA) Specification v1.0.0

```
 _______  _____   ___
|__   __|/ ____| / _ \
   | |  | (___  | |_| |
   | |   \___ \ |  _  |
   | |   ____) || | | |
   |_|  |_____/ |_| |_|
```

Machine-readable security advisories for MCP (Model Context Protocol) tools.

TSA defines a JSON format, a feed index, and a trust model that let registries,
hosts, and gateways automatically block, warn, or remediate vulnerable MCP tools.
It is designed for AI agent ecosystems where traditional formats (CSAF/OSV/VEX)
miss critical MCP-specific concepts such as semantic drift, capability abuse,
and agent execution context.

---

## At a Glance

- **What it is:** A spec, schema, and reference tooling for MCP tool security advisories.
- **Why it exists:** Traditional vuln formats lack MCP-native primitives (TBOM binding,
  semantic drift, capability abuse, agent context, registry actions).
- **What you get:** A strict schema, canonicalization + hashing, signatures, feeds,
  registry SDK, and OSV conversion.
- **Who uses it:** Tool publishers, registries, hosts, gateways, and security teams.

---

## Executive Summary

TSA is a security advisory standard for MCP tools that enables automatic enforcement
of security decisions across registries, hosts, and gateways. It combines a strict
JSON schema with a lightweight feed index and a practical trust model so advisories
can be validated, verified, and acted on at machine speed. TSA extends traditional
formats with MCP-specific primitives (semantic drift, capability abuse, agent context,
and TBOM content hash binding) that reflect the real attack surface of AI agent tools.
Reference tooling is included so implementers can publish, distribute, and enforce TSA
advisories immediately.

---

## One-Page Summary

TSA is a security advisory standard purpose-built for MCP tool ecosystems. It defines a
strict JSON advisory schema and a lightweight feed format that registries, hosts, and
gateways can validate, verify, and enforce automatically. TSA adds the MCP-specific
primitives missing from traditional formats—semantic drift, capability abuse, agent
execution context, and TBOM content hash binding—so that advisories describe the real
attack surface of tools used by AI agents.

TSA’s trust model is simple and practical: advisories can be signed with modern
algorithms (Ed25519/ES256/ES384/RS256), and consumers can enforce BLOCK actions only
when signatures match trusted publisher keys. Every advisory is canonicalized (RFC 8785)
to guarantee deterministic hashing, enabling reliable integrity checks and reproducible
signing across environments.

The repository includes a working reference implementation: a CLI (`tsactl`) for
validation, signing, and verification; a feed builder; an OSV converter; and a registry
SDK that demonstrates real enforcement behavior. Together, these components make TSA
deployable today without altering existing security pipelines: registry operators can
sync feeds and enforce actions, while publishers can generate advisories with minimal
overhead and full interoperability.

In short: TSA turns MCP tool security into a first-class, enforceable, and verifiable
workflow—bridging the gap between AI agent risk and operational security controls.

---

## The Problem TSA Solves

MCP tools execute inside AI agent workflows. A vulnerability in a tool is not just
an application bug; it can become a prompt injection pivot, a capability escalation,
or a data exfiltration path. Existing standards provide a base, but they do not model:

- **Tool identity beyond package name** (content-hash binding to TBOM)
- **Semantic drift** (behavior changes between versions)
- **Capability abuse** (explicit abused capabilities and attack context)
- **Agent execution context** (whether the agent must run or the user must click)
- **Registry enforcement** (BLOCK/WARN/UPDATE actions encoded in the advisory)

TSA adds those missing primitives in a minimal, machine-enforceable format.

---

## How TSA Works (End-to-End Flow)

```
Publisher            Feed Index             Registry/Host/Gateway
---------           ------------            ----------------------
Advisory JSON  -->  Feed JSON  ---->  Sync  -->  Validate + Hash
  + Signature         (lightweight)          + Verify Signature
  + Canonical Hash                            + Enforce Actions
```

1. **Publishers** produce TSA advisories and sign them.
2. **Feeds** index advisories for efficient syncing.
3. **Consumers** validate, verify, and enforce actions automatically.

---

## What Makes TSA Different

| Challenge | Traditional Format Gap | TSA Feature |
|-----------|------------------------|-------------|
| Tool identity beyond package name | CPE/PURL only | TBOM content hash binding |
| Behavioral drift detection | No concept | `semantic_drift` |
| Capability abuse patterns | Not modeled | `capabilities_abused` |
| Agent-specific attack context | Not modeled | `attack_context` |
| Registry enforcement actions | External/manual | `BLOCK`, `WARN`, `UPDATE`, `REVOKE` |

---

## Key Concepts

### Advisory JSON (Single Source of Truth)
A TSA advisory is a strict JSON document validated against Draft 2020-12 JSON Schema.
Unknown fields are rejected (`additionalProperties: false`).

Core fields include:
- **Identity:** `id`, `publisher`, `tsa_version`
- **Timing:** `published`, `modified`, optional `withdrawn`
- **Impact:** `severity`, `impact_statement`, `references`
- **Affected tools:** `affected[]` with version range semantics
- **Enforcement:** `actions[]` (BLOCK/WARN/UPDATE/INVESTIGATE/REVOKE)
- **Integrity:** `signature` (Ed25519/ES256/ES384/RS256)

### Feed JSON (Fast Sync)
A TSA feed is a lightweight index of advisories, each with:
- `id`, `uri`, `canonical_hash`, `modified`, optional `severity`, `title`, `cve`
- Optional inline `advisory` payload for single-file feeds

### Canonicalization and Hashing
TSA uses RFC 8785 (JSON Canonicalization Scheme) to produce a stable byte sequence
for hashing and signing. Consumers verify `canonical_hash` after fetching advisories.

### Trust Model
Consumers maintain a trust anchor list of publisher keys. With `require_signatures=True`,
BLOCK actions are enforced only when the advisory is signed by a trusted key; otherwise
BLOCK downgrades to WARN with a human-readable explanation.

---

## Repository Contents

| Path | Purpose |
|------|---------|
| `schema/tsa-v1.0.0.schema.json` | TSA advisory schema (Draft 2020-12) |
| `schema/tsa-feed-v1.0.0.schema.json` | TSA feed schema |
| `tools/tsactl.py` | CLI: validate, sign, verify, match, canonicalize, hash |
| `tools/tsa_registry_sdk.py` | SDK for registry enforcement |
| `tools/build_feed.py` | Generate feeds from advisories |
| `tools/osv_converter.py` | TSA <-> OSV conversion |
| `advisories/` | Example advisories (real CVEs) |
| `feeds/` | Sample feed |
| `test-vectors/` | Minimal docs, inventory samples, trust anchors |
| `docs/ADOPTION-PITCH.md` | Integration guide for registries |

---

## Quick Start

### Validate an Advisory

```bash
python3 tools/tsactl.py validate advisories/TSA-2025-0001-mcp-remote-rce.tsa.json
```

### Match Against a Tool Inventory

```bash
python3 tools/tsactl.py match advisories/TSA-2025-0001-mcp-remote-rce.tsa.json test-vectors/sample-inventory.json
```

### Sign and Verify

```bash
# Generate keys (Ed25519/ES256/ES384/RS256)
python3 tools/tsactl.py generate-keys my-org --algorithm Ed25519

# Sign (auto-detects algorithm from key)
python3 tools/tsactl.py sign advisory.tsa.json my-org_private.pem --key-id "my-org:key1"

# Verify
python3 tools/tsactl.py verify advisory-signed.tsa.json my-org_public.pem
```

### Registry Integration (Minimal Example)

```python
from tools.tsa_registry_sdk import TSARegistry

registry = TSARegistry(trust_anchors_path="trust-anchors.json", require_signatures=True)
registry.subscribe_feed("feeds/sample-feed.json")
registry.sync()

result = registry.check_package("mcp-remote", "0.1.14", "npm")
if result.blocked:
    print(result.message)
```

---

## Advisory Anatomy (Illustrative)

```json
{
  "tsa_version": "1.0.0",
  "id": "TSA-2025-0001",
  "published": "2025-07-09T00:00:00Z",
  "modified": "2025-07-09T18:00:00Z",
  "publisher": {
    "name": "MCP Security Working Group",
    "namespace": "https://github.com/mcp-security"
  },
  "title": "mcp-remote OS Command Injection via OAuth Callback URL",
  "affected": [
    {
      "tool": {"name": "mcp-remote", "registry": "npm"},
      "versions": {"introduced": "0.0.5", "fixed": "0.1.16"},
      "status": "AFFECTED",
      "capabilities_abused": ["network:oauth", "process:exec"],
      "attack_context": {"requires_agent_execution": false}
    }
  ],
  "actions": [
    {
      "type": "BLOCK",
      "scope": "REGISTRY",
      "condition": ">=0.0.5 <0.1.16",
      "urgency": "IMMEDIATE",
      "message": "BLOCKED: Critical RCE. Update to >=0.1.16."
    }
  ]
}
```

---

## OSV Interoperability

TSA advisories can be converted to/from OSV. MCP-specific fields are preserved via
OSV `database_specific`. When importing OSV -> TSA, provide `--id` to assign a
canonical TSA ID and preserve OSV IDs in `related_vulnerabilities`.

```bash
python3 tools/osv_converter.py tsa-to-osv advisory.tsa.json -o advisory.osv.json
python3 tools/osv_converter.py osv-to-tsa GHSA-xxxx.json -o advisory.tsa.json --id TSA-2025-0004
```

---

## Testing and Verification

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt -r requirements-dev.txt
make verify
```

Stricter gates (coverage + mutation testing):

```bash
MUTMUT_MAX_CHILDREN=4 make verify-strict
```

---

## Adoption Checklist

For **publishers**:
- Assign a stable TSA ID (`TSA-YYYY-NNNN`) and include authoritative references (CVE/GHSA).
- Sign advisories and publish a trust anchor (`key_id` + public key).
- Provide feeds with valid `canonical_hash` and accurate `modified` timestamps.

For **registries/hosts/gateways**:
- Validate advisories against the schema in strict mode.
- Verify `canonical_hash` after fetching advisories.
- Require signatures for BLOCK actions (or downgrade to WARN when missing).
- Cache advisories and track `modified` for incremental updates.

For **security teams**:
- Define trust anchors and rotation policies.
- Decide enforcement defaults (e.g., WARN on unsigned, BLOCK on signed critical).
- Integrate TSA with existing vuln intelligence (OSV/CSAF).

---

## FAQ

**Is TSA a replacement for OSV/CSAF/VEX?**  
No. TSA is MCP-native and interoperates with OSV; it complements existing formats rather
than replacing them.

**Why does TSA include enforcement actions?**  
Because MCP tool risks are operational. Registries and hosts need machine-readable
signals to block or warn automatically when vulnerable versions are detected.

**What is semantic drift and why does it matter?**  
It captures behavior changes between versions (e.g., tool description or capability
changes) that may indicate malicious modification or supply-chain compromise.

**What if an advisory is unsigned?**  
Consumers may still ingest it, but recommended best practice is to downgrade BLOCK
to WARN unless the advisory is signed by a trusted publisher key.

**How does TSA handle tool identity?**  
TSA supports TBOM content hash binding so advisories can be tied to the actual
tool build, not just a package name.

---

## Requirements

- Python 3.10+
- `jsonschema` (validation)
- `cryptography` (signing/verification)

```bash
pip install jsonschema cryptography
```

---

## Status, Scope, and Non-Goals

**Status:** Community specification for MCP tool security advisories.

**In scope:** MCP tool vulnerabilities, semantic drift, capability abuse, tool integrity,
registry/host/gateway actions, signing and verification.

**Out of scope:** LLM model vulnerabilities, general software CVEs unrelated to MCP tools,
compliance policy formats (use CSAF/VEX or dedicated policy systems).

---

## Documents

- `TSA-SPECIFICATION-v1.0.0.md` (normative spec)
- `docs/ADOPTION-PITCH.md` (integration guide)
- `schema/tsa-v1.0.0.schema.json` (advisory schema)
- `schema/tsa-feed-v1.0.0.schema.json` (feed schema)

---

## License

Apache-2.0

---

Author: MCP Security Working Group
Specification Version: 1.0.0
Last Updated: 2026-02-01
