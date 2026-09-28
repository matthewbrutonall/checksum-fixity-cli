from __future__ import annotations

import argparse
import csv
import json
import sys

from . import __version__
from .core import (
    ALGORITHM_LENGTHS,
    DEFAULT_MAX_FILES,
    FixityError,
    OutputExistsError,
    algorithm_warning,
    generate_manifest,
    has_exceptions,
    hash_paths,
    review_report,
    verify_manifest,
)

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_INVALID = 2
EXIT_OUTPUT_EXISTS = 3
EXIT_DISCREPANCIES = 4


def add_common(parser: argparse.ArgumentParser, include_algorithm: bool = True) -> None:
    if include_algorithm:
        parser.add_argument("--algorithm", choices=sorted(ALGORITHM_LENGTHS), default="sha256")
    parser.add_argument("--format", choices=["json", "text"], default="text")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fixity", description="Local, read-only checksum and fixity operations.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    hash_parser = commands.add_parser("hash", help="Calculate checksums for explicit files.")
    hash_parser.add_argument("paths", nargs="+")
    add_common(hash_parser)
    hash_parser.set_defaults(handler=run_hash)

    manifest_parser = commands.add_parser("manifest", help="Create a checksum manifest.")
    manifest_parser.add_argument("paths", nargs="+")
    manifest_parser.add_argument("--base-dir", default=".")
    manifest_parser.add_argument("--output", required=True)
    manifest_parser.add_argument("--recursive", action="store_true")
    manifest_parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    add_common(manifest_parser)
    manifest_parser.set_defaults(handler=run_manifest)

    verify_parser = commands.add_parser("verify", help="Verify files against a checksum manifest.")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--base-dir")
    add_common(verify_parser)
    verify_parser.set_defaults(handler=run_verify)

    review_parser = commands.add_parser("review", help="Review expected and actual checksum columns in CSV.")
    review_parser.add_argument("--input", required=True)
    review_parser.add_argument("--output-dir")
    review_parser.add_argument("--algorithm", choices=sorted(ALGORITHM_LENGTHS))
    review_parser.add_argument("--verification-date")
    add_common(review_parser, include_algorithm=False)
    review_parser.set_defaults(handler=run_review)
    return parser


def run_hash(args: argparse.Namespace) -> dict:
    return hash_paths(args.paths, args.algorithm)


def run_manifest(args: argparse.Namespace) -> dict:
    return generate_manifest(args.paths, args.base_dir, args.output, args.algorithm, args.recursive, args.max_files)


def run_verify(args: argparse.Namespace) -> dict:
    return verify_manifest(args.manifest, args.base_dir, args.algorithm)


def run_review(args: argparse.Namespace) -> dict:
    return review_report(args.input, args.output_dir, args.algorithm, args.verification_date)


def render_text(result: dict) -> str:
    operation = result["operation"]
    if operation == "hash":
        lines = [f"{row['checksum']}  {row['path']}" for row in result["results"]]
        lines.extend(f"SKIPPED {row['reason']}  {row['path']}" for row in result["skipped"])
        return "\n".join(lines)
    if operation == "manifest":
        return f"Wrote {result['processed']} entries to {result['output']}. Skipped: {len(result['skipped'])}."
    counts = result["counts"]
    summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
    lines = [f"{operation.capitalize()} complete: {summary}."]
    if result.get("outputs"):
        lines.extend(f"Wrote {path}" for path in result["outputs"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except OutputExistsError as error:
        print(str(error), file=sys.stderr)
        return EXIT_OUTPUT_EXISTS
    except (FixityError, OSError, UnicodeError, csv.Error) as error:
        print(str(error), file=sys.stderr)
        return EXIT_INVALID
    except Exception as error:
        print(f"Internal failure: {error}", file=sys.stderr)
        return EXIT_INTERNAL

    warning = result.get("warning") or (algorithm_warning(args.algorithm) if hasattr(args, "algorithm") and args.algorithm else None)
    if warning:
        print(f"Warning: {warning}", file=sys.stderr)
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_text(result))
    return EXIT_DISCREPANCIES if has_exceptions(result) else EXIT_OK
if __name__ == "__main__":
    raise SystemExit(main())
