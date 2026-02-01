# Tool Security Advisory (TSA) Specification

**Version 1.0.0**

## Abstract

This specification defines a machine-readable format for communicating security vulnerabilities, behavioral anomalies, and integrity concerns affecting tools in the Model Context Protocol (MCP) ecosystem. TSA enables registries, hosts, and gateways to automatically block, warn about, or remediate vulnerable tool versions.

## Status

This document is a community specification developed independently of the Model Context Protocol core project. It addresses security gaps specific to AI agent tool ecosystems that are not covered by existing vulnerability standards.

## 1. Introduction

### 1.1 Problem Statement

The MCP ecosystem lacks a standardized mechanism for communicating security information about tools. Existing vulnerability formats (CSAF, OSV, VEX) were designed for traditional software and lack primitives essential for AI agent security:

| Challenge | Traditional Format Gap | TSA Solution |
|-----------|------------------------|--------------|
| Tool identity beyond package name | CPE/PURL only | TBOM content hash binding |
| Behavioral drift detection | No concept | `semantic_drift` field |
| Capability abuse patterns | Not modeled | `capabilities_abused` array |
| Agent-specific attack context | Not modeled | `attack_context` object |
| Registry enforcement actions | External/manual | `BLOCK`, `WARN`, `UPDATE` actions |

### 1.2 Design Goals

1. **Machine-readable**: Enable automated policy enforcement at registries, hosts, and gateways
2. **Verifiable**: Support cryptographic signatures for authenticity
3. **Interoperable**: Convert to/from OSV for integration with existing vulnerability databases
4. **MCP-native**: Include primitives specific to AI agent tool security
5. **Minimal**: Require only essential fields; extend through optional properties

### 1.3 Scope

TSA covers:
- Security vulnerabilities in MCP tools (servers, clients, transports)
- Behavioral anomalies (semantic drift, capability changes)
- Integrity concerns (compromised packages, revoked signatures)
- Recommended remediation actions

TSA does not cover:
- Vulnerabilities in LLMs or AI models themselves
- General software vulnerabilities unrelated to MCP tools
- Compliance or policy violations (use dedicated formats)

## 2. Document Structure

A TSA document is a JSON object conforming to the schema defined in `schema/tsa-v1.0.0.schema.json`.

### 2.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `tsa_version` | string | Specification version (e.g., "1.0.0") |
| `id` | string | Unique identifier (TSA-YYYY-NNNN) |
| `published` | string | ISO 8601 publication timestamp |
| `modified` | string | ISO 8601 last modification timestamp |
| `publisher` | object | Publisher information |
| `title` | string | Human-readable title (10-256 chars) |
| `affected` | array | List of affected tools |
| `actions` | array | Recommended enforcement actions |

### 2.2 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Detailed vulnerability description |
| `severity` | object | CVSS scores and qualitative rating |
| `references` | array | External references (CVE, GHSA, etc.) |
| `related_vulnerabilities` | array | Related CVEs when bundling |
| `workarounds` | array | Temporary mitigations |
| `credits` | array | Researcher attribution |
| `signature` | object | Cryptographic signature |
| `withdrawn` | string | Withdrawal timestamp if retracted |

## 3. Field Definitions

### 3.1 Publisher Object

```json
{
  "name": "MCP Security Working Group",
  "namespace": "https://github.com/mcp-security",
  "contact": "security@example.com",
  "issuing_authority": true
}
```

The `namespace` field MUST be a valid URI. The `issuing_authority` field indicates whether the publisher is authorized to issue advisories for the affected tools.

### 3.2 Affected Entry

Each entry in the `affected` array describes one affected tool:

```json
{
  "tool": {
    "name": "mcp-remote",
    "registry": "npm",
    "purl": "pkg:npm/mcp-remote"
  },
  "versions": {
    "introduced": "0.0.5",
    "fixed": "0.1.16",
    "affected_range": ">=0.0.5 <0.1.16"
  },
  "status": "AFFECTED",
  "impact_statement": "Remote code execution via OAuth callback",
  "capabilities_abused": ["network:oauth", "process:exec"],
  "attack_context": {
    "requires_agent_execution": false,
    "requires_user_interaction": true,
    "attack_complexity": "LOW"
  }
}
```

#### 3.2.1 Status Values

| Status | Meaning |
|--------|---------|
| `AFFECTED` | Tool is vulnerable in specified versions |
| `FIXED` | Vulnerability is fixed in specified versions |
| `UNDER_INVESTIGATION` | Still being analyzed |
| `NOT_AFFECTED` | Tool is confirmed not affected |

#### 3.2.2 Version Range

The `versions` object supports multiple formats:

- `introduced`: First vulnerable version
- `fixed`: First fixed version
- `affected_range`: Semver range expression (e.g., ">=1.0.0 <2.0.0")
- `last_affected`: Last known affected version (when fix is unknown)

#### 3.2.3 Semantic Drift (MCP-specific)

```json
{
  "semantic_drift": {
    "detected": true,
    "description_changed": true,
    "capabilities_changed": true,
    "behavior_changed": false,
    "details": "Tool description no longer mentions data exfiltration capability"
  }
}
```

This field captures behavioral changes between tool versions that may indicate malicious modification or supply chain compromise.

#### 3.2.4 Attack Context (MCP-specific)

```json
{
  "attack_context": {
    "requires_agent_execution": true,
    "requires_user_interaction": false,
    "requires_network_access": true,
    "attack_complexity": "LOW",
    "prerequisites": ["Prompt injection via untrusted input"]
  }
}
```

This field describes the attack surface specific to AI agent environments.

#### 3.2.5 TBOM Binding (MCP-specific)

```json
{
  "tbom_binding": {
    "content_hash": "sha256:abc123...",
    "signature_key_id": "publisher:key1"
  }
}
```

Links the advisory to a specific Tool Bill of Materials (TBOM) content hash for cryptographic verification.

### 3.3 Actions

Actions specify what registries, hosts, and gateways should do:

```json
{
  "type": "BLOCK",
  "scope": "REGISTRY",
  "condition": ">=0.0.5 <0.1.16",
  "urgency": "IMMEDIATE",
  "target_version": "0.1.16",
  "message": "BLOCKED: Critical RCE vulnerability. Update to >=0.1.16"
}
```

#### 3.3.1 Action Types

| Type | Meaning | Typical Response |
|------|---------|------------------|
| `BLOCK` | Prevent installation/execution | Return 403, fail install |
| `WARN` | Allow with security notice | Display warning, log event |
| `UPDATE` | Recommend upgrade | Suggest target version |
| `INVESTIGATE` | Manual review needed | Flag for security team |
| `REVOKE` | Signing key compromised | Invalidate signatures |

#### 3.3.2 Scope Values

| Scope | Where action is enforced |
|-------|--------------------------|
| `REGISTRY` | Package registries (npm, PyPI, etc.) |
| `HOST` | MCP host applications |
| `GATEWAY` | API gateways and proxies |
| `ALL` | All enforcement points |

#### 3.3.3 Urgency Values

| Urgency | Meaning |
|---------|---------|
| `IMMEDIATE` | Action required within hours |
| `HIGH` | Action required within days |
| `MEDIUM` | Action required within weeks |
| `LOW` | Action at next maintenance window |

### 3.4 Severity

```json
{
  "severity": {
    "cvss_v3": {
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
      "score": 9.6
    },
    "cvss_v4": {
      "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
      "score": 9.4
    },
    "qualitative": "CRITICAL"
  }
}
```

The `score` field SHOULD only be included if obtained from an authoritative source (NVD, vendor). Qualitative ratings follow: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.

### 3.5 References

```json
{
  "references": [
    {"type": "CVE", "id": "CVE-2025-6514", "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6514"},
    {"type": "ADVISORY", "id": "GHSA-xxxx", "url": "https://github.com/advisories/GHSA-xxxx"},
    {"type": "FIX", "url": "https://github.com/example/repo/commit/abc123"}
  ]
}
```

Reference types: `CVE`, `ADVISORY`, `ARTICLE`, `FIX`, `REPORT`, `WEB`, `OTHER`.

### 3.6 Signature

```json
{
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "mcp-security-wg:prod-2025",
    "value": "base64-encoded-signature",
    "timestamp": "2025-01-15T12:00:00Z"
  }
}
```

Signatures are computed over the canonical JSON form (RFC 8785) of the document with the `signature` field removed.

## 4. Feed Format

A TSA feed is a lightweight index of advisories for efficient synchronization.

### 4.1 Feed Structure

```json
{
  "feed_version": "1.0.0",
  "generated": "2025-01-15T12:00:00Z",
  "publisher": {
    "name": "MCP Security Working Group",
    "namespace": "https://github.com/mcp-security"
  },
  "advisories": [
    {
      "id": "TSA-2025-0001",
      "uri": "advisories/TSA-2025-0001.tsa.json",
      "canonical_hash": "sha256:abc123...",
      "severity": "CRITICAL",
      "modified": "2025-01-15T12:00:00Z",
      "title": "mcp-remote RCE vulnerability",
      "cve": ["CVE-2025-6514"]
    }
  ]
}
```

Feed entries MAY include an optional `advisory` field containing the full TSA document for inline feeds. When present, `uri` and `canonical_hash` are still REQUIRED and SHOULD correspond to the canonicalized advisory content.

### 4.2 Hash Verification

The `canonical_hash` field contains the SHA-256 hash of the advisory's canonical JSON form. Consumers MUST verify this hash after fetching the advisory.

## 5. Canonicalization

TSA uses RFC 8785 (JSON Canonicalization Scheme) for deterministic serialization:

1. Object keys sorted lexicographically by UTF-16 code units
2. No whitespace between tokens
3. Numbers in shortest decimal form
4. Strings with minimal escaping

This enables reproducible hashing and signature verification.

## 6. Security Considerations

### 6.1 Trust Model

TSA implements a publisher-based trust model:

1. **Trust Anchors**: Consumers maintain a list of trusted publisher keys
2. **Signature Verification**: BLOCK actions SHOULD be verified against trust anchors
3. **Unsigned Advisories**: MAY be treated as WARN-only by security-conscious consumers

### 6.2 Advisory Authenticity

- Publishers SHOULD sign all advisories with Ed25519 or ECDSA
- Consumers SHOULD verify signatures before enforcing BLOCK actions
- Key rotation SHOULD use the `REVOKE` action type

### 6.3 Feed Integrity

- Feeds SHOULD be served over HTTPS
- Consumers SHOULD verify `canonical_hash` for each advisory
- Stale feeds (>24 hours) SHOULD trigger warnings

## 7. Implementation Requirements

### 7.1 Producers (Advisory Publishers)

- MUST generate valid JSON conforming to the schema
- MUST include all required fields
- SHOULD include CVSS scores from authoritative sources
- SHOULD sign advisories with Ed25519

### 7.2 Consumers (Registries, Hosts, Gateways)

- MUST validate advisories against the JSON schema
- MUST reject documents with unknown fields (strict mode)
- SHOULD verify signatures before enforcing BLOCK actions
- SHOULD cache advisories with hash verification

## 8. Interoperability

### 8.1 OSV Conversion

TSA advisories can be converted to/from OSV format for integration with existing vulnerability databases. MCP-specific fields are preserved in the `database_specific` extension. When importing OSV into TSA, publishers SHOULD assign a canonical TSA ID; OSV IDs SHOULD be preserved via `related_vulnerabilities` and/or advisory references.

### 8.2 CSAF/VEX

While TSA does not directly convert to CSAF/VEX, the semantic model is compatible. Organizations using CSAF can reference TSA advisories as external sources.

## 9. IANA Considerations

This specification does not require IANA registration. The `urn:tsa:schema:1.0.0` identifier is used for schema references.

## 10. References

### 10.1 Normative References

- [RFC 8785] Rundgren, A., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020
- [JSON Schema] Wright, A., et al., "JSON Schema: A Media Type for Describing JSON Documents", draft-bhutton-json-schema-01

### 10.2 Informative References

- [OSV Schema] Open Source Security Foundation, "OSV Schema", https://ossf.github.io/osv-schema/
- [CVSS v3.1] FIRST, "Common Vulnerability Scoring System v3.1", https://www.first.org/cvss/v3.1/specification-document
- [CVSS v4.0] FIRST, "Common Vulnerability Scoring System v4.0", https://www.first.org/cvss/v4.0/specification-document
- [MCP] Anthropic, "Model Context Protocol", https://modelcontextprotocol.io/

## Appendix A: Complete Example

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
  "description": "The mcp-remote package before version 0.1.16 is vulnerable to OS command injection through malicious OAuth callback URLs.",
  "severity": {
    "cvss_v3": {
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
      "score": 9.6
    },
    "qualitative": "CRITICAL"
  },
  "affected": [
    {
      "tool": {
        "name": "mcp-remote",
        "registry": "npm",
        "purl": "pkg:npm/mcp-remote"
      },
      "versions": {
        "introduced": "0.0.5",
        "fixed": "0.1.16",
        "affected_range": ">=0.0.5 <0.1.16"
      },
      "status": "AFFECTED",
      "impact_statement": "Remote code execution on the host machine.",
      "capabilities_abused": ["network:oauth", "process:exec"],
      "attack_context": {
        "requires_agent_execution": false,
        "requires_user_interaction": true,
        "attack_complexity": "LOW"
      }
    }
  ],
  "references": [
    {"type": "CVE", "id": "CVE-2025-6514", "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6514"},
    {"type": "ADVISORY", "id": "GHSA-6xpm-ggf7-wc3p", "url": "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p"}
  ],
  "actions": [
    {
      "type": "BLOCK",
      "scope": "REGISTRY",
      "condition": ">=0.0.5 <0.1.16",
      "urgency": "IMMEDIATE",
      "message": "BLOCKED: Critical RCE vulnerability (CVE-2025-6514). Update to >=0.1.16."
    },
    {
      "type": "UPDATE",
      "urgency": "IMMEDIATE",
      "target_version": "0.1.16",
      "message": "Update immediately to version 0.1.16 or later."
    }
  ],
  "credits": [
    {"name": "JFrog Security Research", "organization": "JFrog", "type": "FINDER"}
  ]
}
```

## Appendix B: Schema Locations

- TSA Advisory Schema: `schema/tsa-v1.0.0.schema.json`
- TSA Feed Schema: `schema/tsa-feed-v1.0.0.schema.json`

---

**Document Version:** 1.0.0
**Last Updated:** 2026-02-01
**License:** Apache-2.0
