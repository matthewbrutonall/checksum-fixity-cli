import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def command(*arguments):
    return [sys.executable, "-m", "checksum_fixity_cli.cli", *map(str, arguments)]


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments, cwd=None):
        environment = os.environ.copy()
        source = str(Path(__file__).resolve().parents[1] / "src")
        environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
        return subprocess.run(command(*arguments), cwd=cwd, env=environment, text=True, capture_output=True, check=False)

    def test_hash_json(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "record.txt"
            source.write_text("record", encoding="utf-8")
            completed = self.run_cli("hash", source, "--format", "json")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["processed"], 1)
            self.assertEqual(payload["algorithm"], "sha256")

    def test_verify_mismatch_uses_discrepancy_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "record.txt"
            source.write_text("record", encoding="utf-8")
            manifest = base / "manifest.sha256"
            manifest.write_text(f"{'0' * 64}  record.txt\n", encoding="utf-8")
            before = source.read_bytes()
            completed = self.run_cli("verify", "--manifest", manifest, "--format", "json")
            self.assertEqual(completed.returncode, 4, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["counts"], {"mismatch": 1})
            self.assertEqual(source.read_bytes(), before)

    def test_missing_input_is_reported_as_discrepancy(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.txt"
            completed = self.run_cli("hash", missing, "--format", "json")
            self.assertEqual(completed.returncode, 4)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["skipped"][0]["reason"], "missing_or_not_regular")

    def test_legacy_algorithm_warns_on_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "record.txt"
            source.write_text("record", encoding="utf-8")
            completed = self.run_cli("hash", source, "--algorithm", "md5", "--format", "json")
            self.assertEqual(completed.returncode, 0)
            self.assertIn("legacy", completed.stderr)

    def test_existing_output_uses_exit_code_three(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "record.txt"
            source.write_text("record", encoding="utf-8")
            output = base / "manifest.sha256"
            output.write_text("keep", encoding="utf-8")
            completed = self.run_cli("manifest", source, "--base-dir", base, "--output", output)
            self.assertEqual(completed.returncode, 3)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
