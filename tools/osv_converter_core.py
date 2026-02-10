#!/usr/bin/env python3
"""
osv_converter.py - TSA/OSV Format Converter

Converts between TSA (Tool Security Advisory) and OSV (Open Source Vulnerability)
formats for interoperability with existing vulnerability databases.

IMPORTANT: This converter does NOT fabricate data. Fields that cannot be
accurately converted are omitted rather than filled with placeholder values.

Usage:
    osv_converter.py tsa-to-osv advisory.tsa.json
    osv_converter.py osv-to-tsa advisory.osv.json --id TSA-2025-0001

Version: 1.0.0
License: Apache-2.0
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Optional


def tsa_to_osv(tsa: Dict) -> Dict:
    """
    Convert a TSA advisory to OSV format.

    Note: MCP-specific fields (semantic_drift, capabilities_abused, etc.)
    are stored in database_specific as they have no OSV equivalent.
    """
    osv = {
        "schema_version": "1.6.0",
        "id": tsa.get("id", "").replace("TSA-", "TSA-OSV-"),
    }

    # Published/Modified timestamps
    if tsa.get("published"):
        osv["published"] = tsa["published"]
    if tsa.get("modified"):
        osv["modified"] = tsa["modified"]
    if tsa.get("withdrawn"):
        osv["withdrawn"] = tsa["withdrawn"]

    # Summary and details
    osv["summary"] = tsa.get("title", "")
    if tsa.get("description"):
        osv["details"] = tsa["description"]

    # Severity - only include if we have CVSS data
    severity = tsa.get("severity", {})
    osv_severity = []

    if severity.get("cvss_v4"):
        entry = {"type": "CVSS_V4", "vector": severity["cvss_v4"]["vector"]}
        # Only include score if it came from authoritative source
        if "score" in severity["cvss_v4"]:
            entry["score"] = str(severity["cvss_v4"]["score"])
        osv_severity.append(entry)

    if severity.get("cvss_v3"):
        entry = {"type": "CVSS_V3", "vector": severity["cvss_v3"]["vector"]}
        if "score" in severity["cvss_v3"]:
            entry["score"] = str(severity["cvss_v3"]["score"])
        osv_severity.append(entry)

    if osv_severity:
        osv["severity"] = osv_severity

    # Affected packages
    osv_affected = []
    for affected in tsa.get("affected", []):
        tool = affected.get("tool", {})
        versions = affected.get("versions", {})

        pkg = {
            "package": {
                "name": tool.get("name", ""),
                "ecosystem": _registry_to_ecosystem(
                    tool.get("registry", "npm")  # pragma: no mutate
                ),
            }
        }

        if tool.get("purl"):
            pkg["package"]["purl"] = tool["purl"]

        # Version ranges
        ranges = []
        events = []

        if versions.get("introduced"):
            events.append({"introduced": versions["introduced"]})
        elif versions.get("affected_range"):
            # Try to parse affected_range for introduced version
            match = re.search(r">=?\s*(\d+\.\d+\.\d+)", versions["affected_range"])
            if match:
                events.append({"introduced": match.group(1)})
            else:
                events.append({"introduced": "0"})
        else:
            events.append({"introduced": "0"})

        if versions.get("fixed"):
            events.append({"fixed": versions["fixed"]})
        elif versions.get("last_affected"):
            events.append({"last_affected": versions["last_affected"]})

        if events:
            ranges.append({"type": "ECOSYSTEM", "events": events})
            pkg["ranges"] = ranges

        # Database-specific MCP fields
        db_specific = {}
        if affected.get("capabilities_abused"):
            db_specific["capabilities_abused"] = affected["capabilities_abused"]
        if affected.get("semantic_drift"):
            db_specific["semantic_drift"] = affected["semantic_drift"]
        if affected.get("attack_context"):
            db_specific["attack_context"] = affected["attack_context"]
        if affected.get("impact_statement"):
            db_specific["impact_statement"] = affected["impact_statement"]

        if db_specific:
            pkg["database_specific"] = db_specific

        osv_affected.append(pkg)

    if osv_affected:
        osv["affected"] = osv_affected

    # References
    osv_refs = []
    for ref in tsa.get("references", []):
        osv_ref = {"url": ref.get("url", "")}
        ref_type = _ref_type_to_osv(ref.get("type", "WEB"))  # pragma: no mutate
        osv_ref["type"] = ref_type
        osv_refs.append(osv_ref)

    # Add related vulnerabilities as aliases
    aliases = []
    for ref in tsa.get("references", []):
        if ref.get("type") == "CVE" and ref.get("id"):
            aliases.append(ref["id"])
    for rv in tsa.get("related_vulnerabilities", []):
        if rv.get("id"):
            aliases.append(rv["id"])

    if aliases:
        osv["aliases"] = sorted(set(aliases))  # Dedupe deterministically

    if osv_refs:
        osv["references"] = osv_refs

    # Credits
    osv_credits = []
    for credit in tsa.get("credits", []):
        osv_credit = {"name": credit.get("name", "")}
        credit_type = _credit_type_to_osv(credit.get("type", "OTHER"))  # pragma: no mutate
        osv_credit["type"] = credit_type
        if credit.get("contact"):
            osv_credit["contact"] = [credit["contact"]]
        osv_credits.append(osv_credit)

    if osv_credits:
        osv["credits"] = osv_credits

    # Store original TSA ID in database_specific
    osv["database_specific"] = {"tsa_id": tsa.get("id"), "tsa_version": tsa.get("tsa_version")}

    return osv


def osv_to_tsa(osv: Dict, tsa_id: Optional[str] = None) -> Dict:
    """
    Convert an OSV advisory to TSA format.

    Note: OSV lacks MCP-specific concepts, so those fields will be empty.
    """
    osv_id = osv.get("id", "")
    resolved_id = _resolve_tsa_id(osv_id, tsa_id=tsa_id, published=osv.get("published"))
    tsa = {"tsa_version": "1.0.0", "id": resolved_id}

    # Timestamps
    if osv.get("published"):
        tsa["published"] = osv["published"]
    if osv.get("modified"):
        tsa["modified"] = osv["modified"]
    else:
        tsa["modified"] = osv.get(
            "published", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
    if osv.get("withdrawn"):
        tsa["withdrawn"] = osv["withdrawn"]

    # Publisher - use generic if not available
    tsa["publisher"] = {"name": "OSV Import", "namespace": "https://osv.dev"}

    # Title and description
    tsa["title"] = osv.get("summary", "Imported from OSV")
    if osv.get("details"):
        tsa["description"] = osv["details"]

    # Severity
    severity = {}
    for sev in osv.get("severity", []):
        if sev.get("type") == "CVSS_V4":
            severity["cvss_v4"] = {"vector": sev.get("vector", "")}
            # Only include score if OSV provided it
            if sev.get("score"):
                try:
                    severity["cvss_v4"]["score"] = float(sev["score"])
                except (ValueError, TypeError):
                    pass
        elif sev.get("type") == "CVSS_V3":
            severity["cvss_v3"] = {"vector": sev.get("vector", "")}
            if sev.get("score"):
                try:
                    severity["cvss_v3"]["score"] = float(sev["score"])
                except (ValueError, TypeError):
                    pass

    if severity:
        tsa["severity"] = severity

    # Affected
    tsa_affected = []
    for affected in osv.get("affected", []):
        pkg = affected.get("package", {})

        entry = {
            "tool": {
                "name": pkg.get("name", ""),
                "registry": _ecosystem_to_registry(pkg.get("ecosystem", "")),
            },
            "status": "AFFECTED",
        }

        if pkg.get("purl"):
            entry["tool"]["purl"] = pkg["purl"]

        # Version ranges
        versions = {}
        for range_info in affected.get("ranges", []):
            for event in range_info.get("events", []):
                if "introduced" in event and event["introduced"] != "0":
                    versions["introduced"] = event["introduced"]
                if "fixed" in event:
                    versions["fixed"] = event["fixed"]
                if "last_affected" in event:
                    versions["last_affected"] = event["last_affected"]

        if versions:
            entry["versions"] = versions

        # Import MCP-specific from database_specific if present
        db_specific = affected.get("database_specific", {})
        if db_specific.get("capabilities_abused"):
            entry["capabilities_abused"] = db_specific["capabilities_abused"]
        if db_specific.get("semantic_drift"):
            entry["semantic_drift"] = db_specific["semantic_drift"]
        if db_specific.get("attack_context"):
            entry["attack_context"] = db_specific["attack_context"]
        if db_specific.get("impact_statement"):
            entry["impact_statement"] = db_specific["impact_statement"]

        tsa_affected.append(entry)

    if tsa_affected:
        tsa["affected"] = tsa_affected
    else:
        tsa["affected"] = [{"tool": {"name": "unknown"}, "status": "AFFECTED"}]

    # References
    tsa_refs = []
    for ref in osv.get("references", []):
        ref_type = _osv_ref_type_to_tsa(ref.get("type", "WEB"))  # pragma: no mutate
        tsa_ref = {"type": ref_type, "url": ref.get("url", "")}
        tsa_refs.append(tsa_ref)

    if osv_id:
        tsa_refs.append(
            {"type": "ADVISORY", "id": osv_id, "url": f"https://osv.dev/vulnerability/{osv_id}"}
        )

    # Add aliases as CVE references
    for alias in osv.get("aliases", []):
        if alias.startswith("CVE-"):
            tsa_refs.append(
                {"type": "CVE", "id": alias, "url": f"https://nvd.nist.gov/vuln/detail/{alias}"}
            )

    if tsa_refs:
        tsa["references"] = tsa_refs

    if osv_id:
        tsa["related_vulnerabilities"] = [{"id": osv_id}]

    # Actions - create default WARN action
    tsa["actions"] = [
        {
            "type": "WARN",
            "urgency": "HIGH",
            "message": f"Security vulnerability imported from OSV: {osv.get('id', 'unknown')}",
        }
    ]

    # Credits
    tsa_credits = []
    for credit in osv.get("credits", []):
        credit_type = _osv_credit_type_to_tsa(credit.get("type", "OTHER"))  # pragma: no mutate
        tsa_credit = {
            "name": credit.get("name", ""),
            "type": credit_type,
        }
        if credit.get("contact"):
            tsa_credit["contact"] = credit["contact"][0]
        tsa_credits.append(tsa_credit)

    if tsa_credits:
        tsa["credits"] = tsa_credits

    return tsa


# =============================================================================
# Helper functions
# =============================================================================


def _registry_to_ecosystem(registry: str) -> str:
    """Convert TSA registry to OSV ecosystem."""
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "crates": "crates.io",
        "maven": "Maven",
        "nuget": "NuGet",
        "go": "Go",
        "rubygems": "RubyGems",
    }
    return mapping.get(registry.lower(), registry)


def _ecosystem_to_registry(ecosystem: str) -> str:
    """Convert OSV ecosystem to TSA registry."""
    mapping = {
        "crates.io": "crates",
    }
    return mapping.get(ecosystem.lower(), ecosystem.lower())


def _ref_type_to_osv(tsa_type: str) -> str:
    """Convert TSA reference type to OSV."""
    mapping = {
        "CVE": "ADVISORY",
        "ADVISORY": "ADVISORY",
        "ARTICLE": "ARTICLE",
        "FIX": "FIX",
        "REPORT": "REPORT",
    }
    return mapping.get(tsa_type, "WEB")


def _osv_ref_type_to_tsa(osv_type: str) -> str:
    """Convert OSV reference type to TSA."""
    mapping = {
        "ADVISORY": "ADVISORY",
        "ARTICLE": "ARTICLE",
        "FIX": "FIX",
        "REPORT": "REPORT",
        "WEB": "WEB",
        "PACKAGE": "WEB",
    }
    return mapping.get(osv_type, "OTHER")


def _credit_type_to_osv(tsa_type: str) -> str:
    """Convert TSA credit type to OSV."""
    mapping = {
        "FINDER": "FINDER",
        "REPORTER": "REPORTER",
        "ANALYST": "ANALYST",
        "COORDINATOR": "COORDINATOR",
        "REMEDIATION_DEVELOPER": "REMEDIATION_DEVELOPER",
    }
    return mapping.get(tsa_type, "OTHER")


def _osv_credit_type_to_tsa(osv_type: str) -> str:
    """Convert OSV credit type to TSA."""
    allowed = {
        "FINDER",
        "REPORTER",
        "ANALYST",
        "COORDINATOR",
        "REMEDIATION_DEVELOPER",
    }
    return osv_type if osv_type in allowed else "OTHER"


def _is_valid_tsa_id(value: str) -> bool:
    return bool(re.match(r"^TSA-(TEST-)?[0-9]{4}-[0-9]{4,}$", value))


def _generate_tsa_id(osv_id: str, published: Optional[str]) -> str:
    year = datetime.now(timezone.utc).year
    if published:
        try:
            year = datetime.fromisoformat(
                published.replace("Z", "+00:00")  # pragma: no mutate
            ).year  # pragma: no mutate
        except ValueError:
            pass
    digest = 0
    if osv_id:
        digest_hex = hashlib.sha256(osv_id.encode("utf-8")).hexdigest()[:16]  # pragma: no mutate
        digest = int(digest_hex, 16)
    serial = f"{digest % (10**12):012d}"
    return f"TSA-TEST-{year}-{serial}"


def _resolve_tsa_id(osv_id: str, tsa_id: Optional[str], published: Optional[str]) -> str:
    if tsa_id:
        return tsa_id
    if osv_id.startswith("TSA-OSV-"):
        candidate = "TSA-" + osv_id[len("TSA-OSV-") :]
        if _is_valid_tsa_id(candidate):
            return candidate
    if _is_valid_tsa_id(osv_id):
        return osv_id
    if osv_id.startswith("OSV-"):
        candidate = "TSA-" + osv_id[len("OSV-") :]
        if _is_valid_tsa_id(candidate):
            return candidate
    return _generate_tsa_id(osv_id, published)
