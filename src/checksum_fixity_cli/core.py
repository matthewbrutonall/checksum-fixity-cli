from __future__ import annotations

import csv
import hashlib
import os
import re
from datetime import date
from pathlib import Path
from typing import Iterable

CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_FILES = 10_000
ALGORITHM_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "sha512": 128,
}
LEGACY_ALGORITHMS = {"md5", "sha1"}
REGISTER_HEADERS = [
    "source_row",
    "path",
    "filename",
    "algorithm",
    "expected_checksum",
    "actual_checksum",
    "verification_date",
    "status",
    "exception",
    "rationale",
    "next_action",
]


class FixityError(Exception):
    """Invalid or unsafe operation input."""


class OutputExistsError(FixityError):
    """An output path already exists."""


def algorithm_warning(algorithm: str) -> str | None:
    if algorithm in LEGACY_ALGORITHMS:
        return f"{algorithm.upper()} is supported for legacy compatibility; prefer SHA-256 for new manifests."
    return None


def has_symlink_component(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    return any(candidate.is_symlink() for candidate in (absolute, *absolute.parents))


def hash_file(path: Path, algorithm: str) -> str:
    if has_symlink_component(path):
        raise FixityError(f"Symbolic links are not followed: {path}")
    if not path.is_file():
        raise FixityError(f"Not a regular file: {path}")
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(paths: Iterable[str], recursive: bool, max_files: int) -> tuple[list[Path], list[dict[str, str]]]:
    if max_files < 1:
        raise FixityError("--max-files must be at least 1.")
    files: list[Path] = []
    skipped: list[dict[str, str]] = []
    for supplied in paths:
        path = Path(supplied)
        if has_symlink_component(path):
            skipped.append({"path": str(path), "reason": "symbolic_link_not_followed"})
            continue
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            if not recursive:
                raise FixityError(f"Directory input requires --recursive: {path}")
            _collect_directory(path, files, skipped, max_files)
        else:
            skipped.append({"path": str(path), "reason": "missing_or_not_regular"})
        if len(files) > max_files:
            raise FixityError(f"File count exceeds --max-files ({max_files}). Increase it explicitly after reviewing the scope.")
    unique = {str(path.resolve()): path for path in files}
    ordered = [unique[key] for key in sorted(unique)]
    if len(ordered) > max_files:
        raise FixityError(f"File count exceeds --max-files ({max_files}).")
    return ordered, skipped


def _collect_directory(path: Path, files: list[Path], skipped: list[dict[str, str]], max_files: int) -> None:
    for root, directories, filenames in os.walk(path, followlinks=False):
        root_path = Path(root)
        retained = []
        for directory in directories:
            candidate = root_path / directory
            if candidate.is_symlink():
                skipped.append({"path": str(candidate), "reason": "symbolic_link_not_followed"})
            else:
                retained.append(directory)
        directories[:] = retained
        for filename in filenames:
            candidate = root_path / filename
            if candidate.is_symlink():
                skipped.append({"path": str(candidate), "reason": "symbolic_link_not_followed"})
            elif candidate.is_file():
                files.append(candidate)
                if len(files) > max_files:
                    raise FixityError(f"File count exceeds --max-files ({max_files}). Increase it explicitly after reviewing the scope.")


def refuse_existing_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise OutputExistsError(f"Refusing to overwrite existing output: {path}")
    if has_symlink_component(path.parent):
        raise FixityError(f"Refusing to write through a symbolic-link path: {path}")


def write_new_text(path: Path, content: str) -> None:
    refuse_existing_output(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(content)


def hash_paths(paths: list[str], algorithm: str) -> dict:
    files, skipped = collect_files(paths, recursive=False, max_files=max(len(paths), 1))
    results = [
        {"path": str(path), "algorithm": algorithm, "checksum": hash_file(path, algorithm)}
        for path in files
    ]
    return base_result("hash", algorithm, results, skipped)


def generate_manifest(
    paths: list[str],
    base_dir: str,
    output: str,
    algorithm: str,
    recursive: bool,
    max_files: int,
) -> dict:
    supplied_base = Path(base_dir)
    if has_symlink_component(supplied_base):
        raise FixityError(f"Symbolic links are not followed: {supplied_base}")
    resolved_base = supplied_base.resolve()
    if not resolved_base.is_dir():
        raise FixityError(f"Base directory does not exist: {resolved_base}")
    output_path = Path(output)
    refuse_existing_output(output_path)
    files, skipped = collect_files(paths, recursive=recursive, max_files=max_files)
    rows = []
    lines = []
    for path in files:
        relative = relative_manifest_path(path, resolved_base)
        checksum = hash_file(path, algorithm)
        rows.append({"path": relative, "algorithm": algorithm, "checksum": checksum})
        lines.append(f"{checksum}  {relative}")
    write_new_text(output_path, "\n".join(lines) + ("\n" if lines else ""))
    result = base_result("manifest", algorithm, rows, skipped)
    result.update({"output": str(output_path), "baseDirectory": str(resolved_base)})
    return result


def relative_manifest_path(path: Path, base_dir: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(base_dir)
    except ValueError as error:
        raise FixityError(f"Path is outside the declared base directory: {path}") from error
    value = relative.as_posix()
    if "\n" in value or "\r" in value:
        raise FixityError(f"Manifest paths cannot contain line breaks: {path}")
    return value


def parse_manifest(path: Path, algorithm: str) -> tuple[list[dict], list[dict]]:
    expected_length = ALGORITHM_LENGTHS[algorithm]
    entries = []
    invalid = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            match = re.match(r"^([0-9A-Fa-f]+)\s+[ *]?(.*)$", line)
            if not match or not match.group(2):
                invalid.append({"line": line_number, "status": "invalid_manifest_line"})
                continue
            checksum, relative_path = match.groups()
            if len(checksum) != expected_length:
                invalid.append({"line": line_number, "path": relative_path, "status": "invalid_checksum_length"})
                continue
            entries.append({"line": line_number, "path": relative_path, "expected": checksum.lower()})
    return entries, invalid


def verify_manifest(manifest: str, base_dir: str | None, algorithm: str) -> dict:
    manifest_path = Path(manifest)
    if has_symlink_component(manifest_path) or not manifest_path.is_file():
        raise FixityError(f"Manifest is not a regular file: {manifest_path}")
    supplied_base = Path(base_dir) if base_dir else manifest_path.parent
    if has_symlink_component(supplied_base):
        raise FixityError(f"Symbolic links are not followed: {supplied_base}")
    resolved_base = supplied_base.resolve()
    if not resolved_base.is_dir():
        raise FixityError(f"Base directory does not exist: {resolved_base}")
    entries, invalid = parse_manifest(manifest_path, algorithm)
    results = []
    for entry in entries:
        requested = resolved_base / entry["path"]
        resolved = requested.resolve()
        try:
            resolved.relative_to(resolved_base)
        except ValueError:
            results.append({**entry, "status": "unsafe_path"})
            continue
        if has_symlink_component(requested):
            results.append({**entry, "status": "symbolic_link_refused"})
        elif not resolved.is_file():
            results.append({**entry, "status": "missing"})
        else:
            actual = hash_file(resolved, algorithm)
            status = "match" if actual.lower() == entry["expected"] else "mismatch"
            results.append({**entry, "actual": actual, "status": status})
    results.extend(invalid)
    counts = count_statuses(results)
    return {
        "tool": "checksum-fixity-cli",
        "toolVersion": "0.1.0",
        "operation": "verify",
        "algorithm": algorithm,
        "warning": algorithm_warning(algorithm),
        "manifest": str(manifest_path),
        "baseDirectory": str(resolved_base),
        "counts": counts,
        "results": results,
        "caveat": "Checksum agreement confirms bit-level agreement with the supplied expected value; it does not prove provenance or authenticity.",
    }


PATH_HEADERS = {"path", "filepath", "file path", "filename", "file name", "name"}
EXPECTED_HEADERS = {"expected checksum", "expected", "expected sha256", "expected md5", "stored checksum", "manifest checksum"}
ACTUAL_HEADERS = {"actual checksum", "actual", "actual sha256", "computed checksum", "verified checksum", "verification checksum", "fixity checksum"}
CHECKSUM_HEADERS = {"checksum", "sha256", "sha 256", "sha1", "sha 1", "md5"}
ALGORITHM_HEADERS = {"algorithm", "checksum algorithm", "hash algorithm"}
DATE_HEADERS = {"verification date", "date checked", "checked date", "date", "verified at"}


def review_report(
    input_path: str,
    output_dir: str | None,
    default_algorithm: str | None,
    default_date: str | None,
) -> dict:
    source = Path(input_path)
    if has_symlink_component(source) or not source.is_file():
        raise FixityError(f"Input is not a regular CSV file: {source}")
    rows = parse_review_csv(source, default_algorithm, default_date)
    counts = count_statuses(rows)
    result = {
        "tool": "checksum-fixity-cli",
        "toolVersion": "0.1.0",
        "operation": "review",
        "input": str(source),
        "counts": counts,
        "rows": rows,
        "caveat": "This review compares supplied strings only; it does not show that the referenced files were opened or hashed.",
    }
    if output_dir:
        directory = Path(output_dir)
        outputs = [
            directory / "fixity-register.csv",
            directory / "fixity-exceptions.csv",
            directory / "fixity-record.md",
        ]
        for output in outputs:
            refuse_existing_output(output)
        directory.mkdir(parents=True, exist_ok=True)
        write_register_csv(outputs[0], rows)
        write_register_csv(outputs[1], [row for row in rows if row["status"] != "match"])
        write_new_text(outputs[2], build_review_markdown(rows, counts))
        result["outputs"] = [str(output) for output in outputs]
    return result


def parse_review_csv(source: Path, default_algorithm: str | None, default_date: str | None) -> list[dict]:
    with source.open("r", encoding="utf-8-sig", newline="") as stream:
        sample = stream.read(8192)
        stream.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(stream, dialect=dialect)
        fieldnames = reader.fieldnames or []
        path_header = find_header(fieldnames, PATH_HEADERS)
        if not path_header:
            raise FixityError("Delimited reports require a recognised path or filename column.")
        expected_header = find_header(fieldnames, EXPECTED_HEADERS)
        actual_header = find_header(fieldnames, ACTUAL_HEADERS)
        checksum_header = find_header(fieldnames, CHECKSUM_HEADERS)
        algorithm_header = find_header(fieldnames, ALGORITHM_HEADERS)
        date_header = find_header(fieldnames, DATE_HEADERS)
        if not expected_header and checksum_header:
            expected_header = checksum_header
        if not expected_header and not actual_header:
            raise FixityError("Delimited reports require an expected or actual checksum column.")
        rows = []
        for source_row, row in enumerate(reader, start=2):
            supplied_path = (row.get(path_header) or "").strip()
            if not supplied_path:
                continue
            expected = (row.get(expected_header) or "").strip() if expected_header else ""
            actual = (row.get(actual_header) or "").strip() if actual_header else ""
            status = review_status(expected, actual)
            algorithm = ((row.get(algorithm_header) or "").strip() if algorithm_header else "") or default_algorithm or infer_algorithm(expected or actual) or ""
            verification_date = ((row.get(date_header) or "").strip() if date_header else "") or default_date or ""
            rows.append(build_register_row(source_row, supplied_path, algorithm, expected, actual, verification_date, status))
        return rows


def normalized_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def find_header(fieldnames: list[str], candidates: set[str]) -> str | None:
    normalized = {field: normalized_header(field) for field in fieldnames}
    exact = next((field for field, value in normalized.items() if value in candidates), None)
    if exact:
        return exact
    return next((field for field, value in normalized.items() if any(candidate in value for candidate in candidates)), None)


def infer_algorithm(checksum: str) -> str:
    by_length = {length: algorithm for algorithm, length in ALGORITHM_LENGTHS.items()}
    return by_length.get(len(checksum), "")


def review_status(expected: str, actual: str) -> str:
    if not expected and not actual:
        return "missing_checksums"
    if not expected:
        return "missing_expected"
    if not actual:
        return "missing_actual"
    return "match" if expected.lower() == actual.lower() else "mismatch"


def build_register_row(
    source_row: int,
    supplied_path: str,
    algorithm: str,
    expected: str,
    actual: str,
    verification_date: str,
    status: str,
) -> dict:
    messages = status_messages(status)
    normalized_path = supplied_path.replace("\\", "/").rstrip("/")
    return {
        "source_row": source_row,
        "path": supplied_path,
        "filename": normalized_path.rsplit("/", 1)[-1],
        "algorithm": algorithm,
        "expected_checksum": expected,
        "actual_checksum": actual,
        "verification_date": verification_date,
        "status": status,
        **messages,
    }


def status_messages(status: str) -> dict[str, str]:
    values = {
        "match": (
            "",
            "The supplied expected and actual checksum values match.",
            "Record the verification outcome.",
        ),
        "mismatch": (
            "Expected and actual checksums do not match.",
            "The supplied expected and actual checksum values differ.",
            "Re-run local verification and begin preservation incident review; do not overwrite automatically.",
        ),
        "missing_expected": (
            "Expected checksum was not supplied.",
            "No expected value is available for comparison.",
            "Locate the original manifest or trusted repository metadata.",
        ),
        "missing_actual": (
            "Actual verification checksum was not supplied.",
            "No calculated value is available for comparison.",
            "Run local fixity verification and record the resulting checksum.",
        ),
        "missing_checksums": (
            "Neither expected nor actual checksum was supplied.",
            "No checksum evidence is available for comparison.",
            "Supply checksum evidence before making a fixity finding.",
        ),
    }
    exception, rationale, next_action = values[status]
    return {"exception": exception, "rationale": rationale, "next_action": next_action}


def write_register_csv(path: Path, rows: list[dict]) -> None:
    refuse_existing_output(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=REGISTER_HEADERS)
        writer.writeheader()
        writer.writerows(rows)


def build_review_markdown(rows: list[dict], counts: dict[str, int]) -> str:
    exceptions = [row for row in rows if row["status"] != "match"]
    lines = [
        "# Draft Checksum / Fixity Register",
        "",
        f"Generated locally on {date.today().isoformat()} from a supplied report.",
        "",
        "## Summary",
        "",
        f"- listed files: {len(rows)}",
        f"- matches: {counts.get('match', 0)}",
        f"- mismatches: {counts.get('mismatch', 0)}",
        f"- missing expected checksums: {counts.get('missing_expected', 0)}",
        f"- missing actual checksums: {counts.get('missing_actual', 0)}",
        f"- missing both checksums: {counts.get('missing_checksums', 0)}",
        "",
        "## Exceptions",
        "",
    ]
    lines.extend(f"- {row['path']} | {row['status']} | {row['next_action']}" for row in exceptions)
    if not exceptions:
        lines.append("- None recorded by this draft.")
    lines.extend([
        "",
        "## Caveat",
        "",
        "This review compares supplied strings only. It does not show that the referenced files were opened or hashed, and it does not prove provenance or authenticity.",
        "",
    ])
    return "\n".join(lines)


def count_statuses(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row["status"])
        counts[status] = counts.get(status, 0) + 1
    return counts


def base_result(operation: str, algorithm: str, results: list[dict], skipped: list[dict]) -> dict:
    return {
        "tool": "checksum-fixity-cli",
        "toolVersion": "0.1.0",
        "operation": operation,
        "algorithm": algorithm,
        "warning": algorithm_warning(algorithm),
        "processed": len(results),
        "skipped": skipped,
        "results": results,
        "caveat": "Checksums describe file bytes under the stated algorithm; they do not prove provenance or authenticity.",
    }


def has_exceptions(result: dict) -> bool:
    if result.get("skipped"):
        return True
    if result.get("operation") in {"verify", "review"}:
        return any(row.get("status") != "match" for row in result.get("results", result.get("rows", [])))
    return False
