"""The local-only AgentProof command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .core import ManifestError, SEVERITIES, evaluate, load_document, markdown, scan_mcp, validate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentproof", description="Review agent declarations and MCP configurations offline")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="discover server names and transports from an MCP JSON config")
    scan.add_argument("--input", required=True, help="path to an MCP JSON config")
    scan.add_argument("--output", required=True, help="path to the resulting manifest")
    scan.add_argument("--name", default="scanned-agent")
    verify = sub.add_parser("verify", help="validate and assess a manifest")
    verify.add_argument("manifest")
    verify.add_argument("--format", choices=["json", "markdown"], default="markdown")
    verify.add_argument("--output")
    verify.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="high")
    check = sub.add_parser("validate", help="check a manifest against the AAM schema")
    check.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            manifest = scan_mcp(args.input, args.name)
            validate(manifest)
            output = yaml.safe_dump(manifest, sort_keys=False)
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Wrote {args.output}; review and complete the unknown identity, capabilities and controls before relying on it")
        elif args.command == "validate":
            validate(load_document(args.manifest))
            print("Valid AAM v0alpha1 manifest")
        else:
            report = evaluate(load_document(args.manifest))
            output = json.dumps(report, indent=2) + "\n" if args.format == "json" else markdown(report)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"Wrote {args.output}")
            else:
                print(output, end="")
            if args.fail_on != "none" and any(SEVERITIES[f["severity"]] >= SEVERITIES[args.fail_on] for f in report["findings"]):
                return 1
        return 0
    except (ManifestError, OSError, UnicodeError, ValueError) as exc:
        print(f"agentproof: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
