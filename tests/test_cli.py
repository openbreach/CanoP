import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from canop.cli import cli


class CliTests(unittest.TestCase):
    def test_no_arguments_shows_help(self):
        result = CliRunner().invoke(cli, [])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage:", result.output)
        self.assertIn("canop scan .", result.output)
        self.assertIn("Taint modes:", result.output)

    def test_version(self):
        result = CliRunner().invoke(cli, ["--version"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("0.3.3", result.output)

    def test_scan_help_lists_taint_modes(self):
        result = CliRunner().invoke(cli, ["scan", "--help"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("--taint-mode MODE", result.output)
        self.assertIn("fast", result.output)
        self.assertIn("balanced", result.output)
        self.assertIn("deep", result.output)

    def test_taint_mode_requires_a_listed_mode(self):
        result = CliRunner().invoke(cli, ["scan", ".", "--taint-mode"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("requires an argument", result.output)

    def test_scan_exports_json(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text("print('hello')\n", encoding="utf-8")
            output = root / "results.json"

            with patch("canop.semgrep_engine.is_semgrep_available", return_value=False):
                result = runner.invoke(cli, ["scan", str(root), "--json-out", str(output)])

            self.assertEqual(result.exit_code, 0, result.output)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["security_score"], 100)


if __name__ == "__main__":
    unittest.main()
