#!/usr/bin/env python3
"""
tsa_registry_sdk.py - TSA Registry Integration SDK

CLI/demo wrapper for the TSA Registry SDK.
Core logic lives in tools/tsa_registry_sdk_core.py.
"""

import tools.tsa_registry_sdk_core as _core


def __getattr__(name: str):
    return getattr(_core, name)


def demo():
    """Demonstrate the TSA Registry SDK with a real advisory."""
    print("=" * 60)
    print("TSA Registry SDK Demo")
    print("=" * 60)

    registry = _core.TSARegistry()

    sample_advisory = {
        "tsa_version": "1.0.0",
        "id": "TSA-2025-0001",
        "published": "2025-07-09T00:00:00Z",
        "modified": "2025-07-09T18:00:00Z",
        "publisher": {
            "name": "MCP Security Working Group",
            "namespace": "https://tsa.mcp.security",
        },
        "title": "mcp-remote OS Command Injection via OAuth Callback",
        "severity": {
            "cvss_v3": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                "score": 9.6,
            },
            "qualitative": "CRITICAL",
        },
        "affected": [
            {
                "tool": {"name": "mcp-remote", "registry": "npm"},
                "versions": {
                    "introduced": "0.0.5",
                    "fixed": "0.1.16",
                    "affected_range": ">=0.0.5 <0.1.16",
                },
                "status": "AFFECTED",
                "impact_statement": "Remote code execution via malicious OAuth callback URL",
            }
        ],
        "actions": [
            {
                "type": "BLOCK",
                "condition": ">=0.0.5 <0.1.16",
                "urgency": "IMMEDIATE",
                "message": "BLOCKED: Critical RCE (CVE-2025-6514). Update to >=0.1.16",
            }
        ],
        "references": [
            {
                "type": "CVE",
                "id": "CVE-2025-6514",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
            }
        ],
    }

    print("\n1. Adding sample advisory (CVE-2025-6514)...")
    registry.add_advisory(sample_advisory)
    print("   ✓ Indexed: TSA-2025-0001")

    print("\n2. Checking VULNERABLE version (mcp-remote@0.1.14)...")
    result = registry.check_package("mcp-remote", "0.1.14", "npm")
    print(f"   Blocked: {result.blocked}")
    print(f"   Message: {result.message}")

    print("\n3. Checking FIXED version (mcp-remote@0.1.16)...")
    result = registry.check_package("mcp-remote", "0.1.16", "npm")
    print(f"   Blocked: {result.blocked}")
    print(f"   Advisories found: {len(result.advisories)}")

    print("\n4. Checking UNAFFECTED package (other-tool@1.0.0)...")
    result = registry.check_package("other-tool", "1.0.0", "npm")
    print(f"   Blocked: {result.blocked}")

    print("\n5. Registry statistics:")
    stats = registry.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n" + "=" * 60)
    print("Demo Complete - SDK is working!")
    print("=" * 60)


if __name__ == "__main__":
    demo()
