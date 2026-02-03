# TSA Adoption Guide for Registry Operators

**Integrate MCP security advisories in under an hour**

This guide shows how to integrate TSA (Tool Security Advisory) into your MCP tool registry to protect users from known vulnerabilities.

## Why Integrate TSA?

1. **Examples included** - `advisories/` includes CVE-2025-6514, CVE-2025-49596, and CVE-2025-53109/53110
2. **Users expect protection** - Modern registries increasingly surface warnings or restrictions for known-vulnerable versions
3. **Machine-readable format** - No more manually parsing security announcements
4. **5-line integration** - The SDK handles feed sync, matching, and policy enforcement

## Integration Paths

### Path 1: SDK Integration (Recommended)

The TSA Registry SDK provides a complete solution:

```python
from tools.tsa_registry_sdk import TSARegistry

# Initialize once at startup
registry = TSARegistry(
    trust_anchors_path="trust-anchors.json",  # Optional: verify signatures
    require_signatures=False  # Set True for production
)

# Subscribe to feeds
registry.subscribe_feed("https://tsa.mcp.security/feed.json")

# Sync periodically (e.g., every hour via cron/scheduler)
registry.sync()

# Check packages on install/publish
def check_before_install(package_name, version, registry_type="npm"):
    result = registry.check_package(package_name, version, registry_type)
    
    if result.blocked:
        raise SecurityError(result.message)
    
    for warning in result.warnings:
        log_warning(warning)
    
    return True
```

### Path 2: Feed-Only Integration

If you can't use the SDK, consume the feed directly:

```python
import requests
import json

def sync_advisories():
    feed = requests.get("https://tsa.mcp.security/feed.json").json()
    
    for entry in feed["advisories"]:
        advisory_url = entry["uri"]
        expected_hash = entry["canonical_hash"]
        
        # Fetch and verify
        advisory = requests.get(advisory_url).json()
        actual_hash = compute_canonical_hash(advisory)
        
        if actual_hash != expected_hash:
            log_error(f"Hash mismatch for {entry['id']}")
            continue
        
        # Store in your database
        store_advisory(advisory)
```

### Path 3: CLI Integration

For shell-based workflows:

```bash
# Validate advisory
python3 tools/tsactl.py validate advisory.tsa.json

# Check inventory (returns exit code 2 if vulnerabilities found)
python3 tools/tsactl.py match advisory.tsa.json inventory.json
if [ $? -eq 2 ]; then
    echo "Vulnerabilities found!"
fi
```

## Feed Format

TSA feeds are JSON files listing available advisories:

```json
{
  "feed_version": "1.0.0",
  "generated": "2025-01-16T00:00:00Z",
  "publisher": {
    "name": "Example Publisher",
    "namespace": "https://example.com"
  },
  "advisories": [
    {
      "id": "TSA-2025-0001",
      "title": "mcp-remote OS Command Injection",
      "severity": "CRITICAL",
      "canonical_hash": "sha256:abc123...",
      "uri": "https://tsa.mcp.security/advisories/TSA-2025-0001.json"
    }
  ]
}
```

## Action Types

TSA advisories specify what registries should do:

| Action | Meaning | Registry Response |
|--------|---------|-------------------|
| `BLOCK` | Prevent installation | Return 403, fail install |
| `WARN` | Allow with warning | Display security notice |
| `UPDATE` | Suggest upgrade | Show available fix |
| `INVESTIGATE` | Manual review needed | Flag for security team |
| `REVOKE` | Key compromised | Invalidate signatures |

## Signature Verification (Recommended for Production)

For high-security deployments, verify advisory signatures (Ed25519/ES256/ES384/RS256):

```python
registry = TSARegistry(
    trust_anchors_path="trust-anchors.json",
    require_signatures=True  # Unsigned/invalid/non-full BLOCK actions become WARN
)
```

Trust anchors file:
```json
{
  "anchors": [
    {
      "key_id": "mcp-security-wg:prod-2025",
      "publisher": "MCP Security Working Group",
      "trust_level": "full",
      "public_key": "-----BEGIN PUBLIC KEY-----\n..."
    }
  ]
}
```

## Caching Strategy

Recommendations for production:

1. **Sync frequency**: Every 1-4 hours
2. **Cache feeds locally**: Reduce latency, handle outages
3. **Verify hashes**: Detect tampering or corruption
4. **Graceful degradation**: If sync fails, use cached data

```python
def sync_with_fallback():
    try:
        stats = registry.sync()
        save_cache(registry.advisories)
    except Exception as e:
        log_error(f"Sync failed: {e}")
        load_cache()  # Fall back to cached advisories
```

## Metrics to Track

Monitor these for security posture:

- Advisories synced (total, by severity)
- Packages blocked per day
- Warnings shown per day
- Sync failures
- Time since last successful sync

## Testing Your Integration

Use the sample inventory to verify matching:

```bash
# Should find 1 vulnerable package
python3 tools/tsactl.py match advisories/TSA-2025-0001-mcp-remote-rce.tsa.json test-vectors/sample-inventory.json
```

Expected output:
```
⚠ Found 1 affected tool(s):

  mcp-remote@0.1.14 (npm)
    Advisory: TSA-2025-0001
    Severity: CRITICAL
    Fixed in: 0.1.16
    Impact: Remote code execution on the host machine...
```

## Support

- **Schema**: `schema/tsa-v1.0.0.schema.json`
- **Reference implementation**: `tools/tsactl.py`
- **SDK**: `tools/tsa_registry_sdk.py`

---

**Questions?** Open an issue on the TSA specification repository.
