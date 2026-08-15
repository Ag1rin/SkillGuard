"""
cli.py — Command-line entrypoint: `skillguard scan <path>`
"""

import argparse
import sys
import os

from .analyzer import scan_all, VERDICT_BLOCKED
from .report import render_terminal, render_json, render_markdown, _supports_unicode


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _write_output(text):
    """Print report text without crashing on legacy Windows code pages."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.buffer.write((text + "\n").encode(encoding, errors="replace"))


def build_parser():
    p = argparse.ArgumentParser(
        prog="skillguard",
        description="Static security scanner for AI agent Skills (SKILL.md + companion scripts).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a directory of skills")
    scan.add_argument("path", help="Path to a skills directory, or a single skill folder")
    scan.add_argument("--format", choices=["terminal", "json", "markdown"], default="terminal")
    scan.add_argument("--out", help="Write report to this file instead of stdout")
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI color in terminal output")
    scan.add_argument("--fail-on-blocked", action="store_true",
                       help="Exit with a non-zero status if any skill is scored BLOCKED (for CI use)")
    scan.add_argument("--min-severity", type=int, default=0,
                       help="Only show findings at or above this severity (1=LOW..15=CRITICAL)")
    scan.add_argument(
        "--allow-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Treat outbound calls to this domain as declared/expected (repeatable). "
             "Domains declared in SKILL.md network sections are auto-detected.",
    )

    return p


def main(argv=None):
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        if not os.path.isdir(args.path):
            print(f"error: '{args.path}' is not a directory", file=sys.stderr)
            return 2

        reports = scan_all(args.path, extra_allow_domains=args.allow_domain)
        if not reports:
            print(f"No skills found under '{args.path}' (looked for SKILL.md files).", file=sys.stderr)
            return 1

        if args.min_severity:
            for r in reports:
                r.findings = [f for f in r.findings if f.severity >= args.min_severity]

        if args.format == "json":
            output = render_json(reports)
        elif args.format == "markdown":
            output = render_markdown(reports)
        else:
            output = render_terminal(
                reports,
                use_color=not args.no_color and sys.stdout.isatty(),
                use_unicode=_supports_unicode(),
            )

        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output)
            print(f"Report written to {args.out}")
        else:
            _write_output(output)

        if args.fail_on_blocked and any(r.verdict == VERDICT_BLOCKED for r in reports):
            return 1
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
