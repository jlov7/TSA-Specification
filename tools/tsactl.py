#!/usr/bin/env python3
"""
tsactl - Tool Security Advisory Command Line Tool

CLI wrapper for the TSA (Tool Security Advisory) specification.
Core logic lives in tools/tsactl_core.py.
"""

import argparse
import json
import sys

import tools.tsactl_core as _core

BANNER = (
    " _______  _____   ___\n"
    "|__   __|/ ____| / _ \\\n"
    "   | |  | (___  | |_| |\n"
    "   | |   \\___ \\ |  _  |\n"
    "   | |   ____) || | | |\n"
    "   |_|  |_____/ |_| |_|\n"
)
TAGLINE = "Machine-readable security advisories for MCP tools."


def __getattr__(name: str):
    return getattr(_core, name)


def cmd_validate(args):
    """Validate a TSA document."""
    with open(args.tsa_file, "r") as f:
        tsa_doc = json.load(f)

    result = _core.validate_tsa(tsa_doc)
    print(result.summary())

    return 0 if result.valid else 1


def cmd_canonicalize(args):
    """Output canonical form."""
    with open(args.tsa_file, "r") as f:
        tsa_doc = json.load(f)

    print(_core.canonicalize(tsa_doc))
    return 0


def cmd_hash(args):
    """Compute canonical hash."""
    with open(args.tsa_file, "r") as f:
        tsa_doc = json.load(f)

    hash_value = _core.compute_canonical_hash(tsa_doc)
    print(f"{args.tsa_file}: {hash_value}")
    return 0


def cmd_sign(args):
    """Sign a TSA document."""
    if not _core.CRYPTO_AVAILABLE:
        print("Error: cryptography library not installed", file=sys.stderr)
        print("Install with: pip install cryptography", file=sys.stderr)
        return 1

    with open(args.tsa_file, "r") as f:
        tsa_doc = json.load(f)

    signed_doc = _core.sign_document(tsa_doc, args.key_file, args.key_id, args.algorithm)

    output_path = args.output or args.tsa_file.replace(".json", "-signed.json")
    with open(output_path, "w") as f:
        json.dump(signed_doc, f, indent=2)

    print(f"✓ Signed document written to: {output_path}")
    return 0


def cmd_verify(args):
    """Verify TSA signature."""
    if not _core.CRYPTO_AVAILABLE:
        print("Error: cryptography library not installed", file=sys.stderr)
        return 1

    with open(args.tsa_file, "r") as f:
        tsa_doc = json.load(f)

    try:
        if _core.verify_signature(tsa_doc, args.pub_key):
            print("✓ Signature VALID")
            print(f"  Key ID: {tsa_doc['signature']['key_id']}")
            print(f"  Signed: {tsa_doc['signature'].get('timestamp', 'N/A')}")
            return 0
        else:
            print("✗ Signature INVALID")
            return 1
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        return 1


def cmd_match(args):
    """Match advisory against inventory."""
    with open(args.tsa_file, "r") as f:
        tsa_doc = json.load(f)

    with open(args.inventory, "r") as f:
        inventory = json.load(f)

    if isinstance(inventory, dict):
        inventory = inventory.get("tools", [])

    matches = _core.match_advisory(tsa_doc, inventory)

    if matches:
        print(f"⚠ Found {len(matches)} affected tool(s):\n")
        for m in matches:
            print(f"  {m['tool']}@{m['version']} ({m['registry']})")
            print(f"    Advisory: {m['advisory_id']}")
            print(f"    Severity: {m['severity']}")
            print(f"    Fixed in: {m['fixed_version']}")
            if m["impact"]:
                print(f"    Impact: {m['impact'][:80]}...")
            print()
        return 2  # Return 2 if vulnerabilities found
    else:
        print("✓ No affected tools found.")
        return 0


def cmd_generate_keys(args):
    """Generate a key pair for TSA signing."""
    if not _core.CRYPTO_AVAILABLE:
        print("Error: cryptography library not installed", file=sys.stderr)
        print("Install with: pip install cryptography", file=sys.stderr)
        return 1

    private_path, public_path = _core.generate_keys(
        args.prefix, algorithm=args.algorithm, rsa_bits=args.rsa_bits
    )
    print(f"✓ Generated {args.algorithm} key pair:")
    print(f"  Private: {private_path} (chmod 600)")
    print(f"  Public:  {public_path}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=f"TSA (Tool Security Advisory) CLI Tool\n{BANNER}\n{TAGLINE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tsactl validate advisory.tsa.json
  tsactl hash advisory.tsa.json
  tsactl sign advisory.tsa.json my-org_private.pem --key-id "my-org:key1"
  tsactl sign advisory.tsa.json my-org_private.pem --key-id "my-org:key1" --algorithm RS256
  tsactl verify signed.tsa.json my-org_public.pem
  tsactl match advisory.tsa.json inventory.json
  tsactl generate-keys my-org
  tsactl generate-keys my-org --algorithm RS256 --rsa-bits 2048
        """,
    )
    parser.add_argument("--version", action="version", version="tsactl 1.0.0")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate TSA document against schema")
    validate_parser.add_argument("tsa_file", help="TSA JSON file")
    validate_parser.set_defaults(func=cmd_validate)

    # canonicalize
    canon_parser = subparsers.add_parser("canonicalize", help="Output canonical form (RFC 8785)")
    canon_parser.add_argument("tsa_file", help="TSA JSON file")
    canon_parser.set_defaults(func=cmd_canonicalize)

    # hash
    hash_parser = subparsers.add_parser("hash", help="Compute canonical SHA-256 hash")
    hash_parser.add_argument("tsa_file", help="TSA JSON file")
    hash_parser.set_defaults(func=cmd_hash)

    # sign
    sign_parser = subparsers.add_parser(
        "sign", help="Sign TSA document (auto/Ed25519/ES256/ES384/RS256)"
    )
    sign_parser.add_argument("tsa_file", help="TSA JSON file")
    sign_parser.add_argument("key_file", help="Private key file")
    sign_parser.add_argument("--key-id", required=True, help="Key ID (e.g., org:key1)")
    sign_parser.add_argument(
        "--algorithm",
        default="auto",
        choices=["auto", "Ed25519", "ES256", "ES384", "RS256"],
        help="Signature algorithm (default: auto-detect from key)",
    )
    sign_parser.add_argument("--output", help="Output file for signed document")
    sign_parser.set_defaults(func=cmd_sign)

    # verify
    verify_parser = subparsers.add_parser(
        "verify", help="Verify signature (Ed25519/ES256/ES384/RS256)"
    )
    verify_parser.add_argument("tsa_file", help="TSA JSON file")
    verify_parser.add_argument("pub_key", help="Public key file")
    verify_parser.set_defaults(func=cmd_verify)

    # match
    match_parser = subparsers.add_parser("match", help="Match advisory against tool inventory")
    match_parser.add_argument("tsa_file", help="TSA JSON file")
    match_parser.add_argument("inventory", help="Inventory JSON file")
    match_parser.set_defaults(func=cmd_match)

    # generate-keys
    gen_parser = subparsers.add_parser(
        "generate-keys", help="Generate key pair for Ed25519/ES256/ES384/RS256"
    )
    gen_parser.add_argument("prefix", help="Output filename prefix")
    gen_parser.add_argument(
        "--algorithm",
        default="Ed25519",
        choices=["Ed25519", "ES256", "ES384", "RS256"],
        help="Key algorithm (default: Ed25519)",
    )
    gen_parser.add_argument(
        "--rsa-bits",
        type=int,
        default=2048,
        help="RSA key size (default: 2048)",
    )
    gen_parser.set_defaults(func=cmd_generate_keys)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
