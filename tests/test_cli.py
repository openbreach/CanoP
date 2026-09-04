import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from canop.cli import cli


class CliTests(unittest.TestCase):
    def test_version(self):
        result = CliRunner().invoke(cli, ["--version"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("0.3.2", result.output)

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
