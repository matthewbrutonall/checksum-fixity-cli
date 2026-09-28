import csv
import hashlib
import tempfile
import unittest
from pathlib import Path

from checksum_fixity_cli.core import (
    FixityError,
    OutputExistsError,
    collect_files,
    generate_manifest,
    hash_file,
    review_report,
    verify_manifest,
)


class CoreTests(unittest.TestCase):
    def test_hashes_file_in_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.bin"
            path.write_bytes(b"archive" * 200_000)
            self.assertEqual(hash_file(path, "sha256"), hashlib.sha256(path.read_bytes()).hexdigest())

    def test_manifest_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "records" / "one file.txt"
            source.parent.mkdir()
            source.write_text("record", encoding="utf-8")
            manifest = base / "reports" / "transfer.sha256"
            generated = generate_manifest([str(source)], str(base), str(manifest), "sha256", False, 10)
            self.assertEqual(generated["processed"], 1)
            verified = verify_manifest(str(manifest), str(base), "sha256")
            self.assertEqual(verified["counts"], {"match": 1})

    def test_verify_reports_unsafe_path(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manifest = base / "manifest.sha256"
            manifest.write_text(f"{'0' * 64}  ../outside.txt\n", encoding="utf-8")
            result = verify_manifest(str(manifest), str(base), "sha256")
            self.assertEqual(result["counts"], {"unsafe_path": 1})

    def test_manifest_refuses_directory_without_recursive(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with self.assertRaises(FixityError):
                generate_manifest([str(base)], str(base), str(base / "manifest.sha256"), "sha256", False, 10)

    def test_manifest_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "record.txt"
            source.write_text("record", encoding="utf-8")
            output = base / "manifest.sha256"
            output.write_text("keep", encoding="utf-8")
            with self.assertRaises(OutputExistsError):
                generate_manifest([str(source)], str(base), str(output), "sha256", False, 10)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_review_writes_full_and_exception_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report = base / "report.csv"
            with report.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["path", "expected_checksum", "actual_checksum"])
                writer.writerow(["match.tif", "ABC", "abc"])
                writer.writerow(["different.tif", "abc", "def"])
            result = review_report(str(report), str(base / "review"), "sha256", "2026-09-28")
            self.assertEqual(result["counts"]["match"], 1)
            with (base / "review" / "fixity-exceptions.csv").open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([row["path"] for row in rows], ["different.tif"])

    def test_recursive_manifest_skips_symbolic_links(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "record.txt"
            source.write_text("record", encoding="utf-8")
            linked = base / "linked.txt"
            linked.symlink_to(source)
            output = base / "reports" / "manifest.sha256"
            result = generate_manifest([str(base)], str(base), str(output), "sha256", True, 10)
            self.assertEqual(result["processed"], 1)
            self.assertEqual(result["skipped"], [{"path": str(linked), "reason": "symbolic_link_not_followed"}])
            self.assertNotIn("linked.txt", output.read_text(encoding="utf-8"))

    def test_recursive_collection_enforces_file_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "one.txt").write_text("one", encoding="utf-8")
            (base / "two.txt").write_text("two", encoding="utf-8")
            with self.assertRaises(FixityError):
                collect_files([str(base)], recursive=True, max_files=1)


if __name__ == "__main__":
    unittest.main()
