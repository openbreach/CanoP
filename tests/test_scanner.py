import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from canop.scanner import export_sarif, run_scan


class ScannerTests(unittest.TestCase):
    def scan_files(self, files, ignore=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                file_path = root / name
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(content, encoding="utf-8")
            if ignore:
                (root / ".canopignore").write_text(ignore, encoding="utf-8")
            with patch("canop.semgrep_engine.is_semgrep_available", return_value=False):
                return run_scan(str(root))

    def test_detects_sensitive_value_printed_to_stdout(self):
        result = self.scan_files({"app.py": "password = input()\nprint(password)\n"})

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "MEDIUM")
        self.assertEqual(result["findings"][0]["category"], "information-exposure")
        self.assertEqual(result["security_score"], 96)
        self.assertEqual(result["security_grade"], "A")

    def test_safe_code_has_no_findings(self):
        result = self.scan_files({"app.py": "print('hello')\n"})

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["security_score"], 100)
        self.assertEqual(result["security_grade"], "A+")

    def test_detects_secrets_in_frontend_comments(self):
        result = self.scan_files(
            {
                "app.tsx": (
                    '// AWS access key: AKIA1234567890ABCDEF\n'
                    '// GitHub token: ghp_123456789012345678901234567890123456\n'
                    '/* private key: -----BEGIN PRIVATE KEY----- */\n'
                )
            }
        )

        rule_ids = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("CANOP-AWS-ACCESS-KEY", rule_ids)
        self.assertIn("CANOP-GITHUB-TOKEN", rule_ids)
        self.assertIn("CANOP-PRIVATE-KEY-PEM", rule_ids)

    def test_still_ignores_non_secret_patterns_in_comments(self):
        result = self.scan_files({"app.js": "// eval(userInput)\n"})

        self.assertEqual(result["findings"], [])

    def test_canopignore_excludes_files(self):
        result = self.scan_files(
            {"ignored.py": "password = input()\nprint(password)\n"},
            ignore="ignored.py\n",
        )

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["files_skipped_ignore"], 1)

    def test_sarif_contains_release_metadata_and_findings(self):
        result = self.scan_files({"app.py": "password = input()\nprint(password)\n"})

        sarif = export_sarif(result)
        driver = sarif["runs"][0]["tool"]["driver"]

        self.assertEqual(driver["version"], "0.3.3")
        self.assertEqual(driver["informationUri"], "https://github.com/openbreach/CanoP")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        json.dumps(sarif)


if __name__ == "__main__":
    unittest.main()
