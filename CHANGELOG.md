# Changelog

All notable changes to CanoP are documented here.

## 0.3.4 - 2026-10-28

- Fixed YAML quoting in three security rule files so all 46 bundled rule files and 646 rules parse successfully.

## 0.3.3 - 2026-10-19

- Detects secrets accidentally left in frontend comments.
- Adds regression coverage for commented credentials and preserves comment filtering for other rules.
- Shortens the README while retaining usage, configuration, release, and detection guidance.

## 0.3.2 - 2026-09-04

- Added focused scanner and CLI regression tests.
- Added GitHub Actions CI for supported Python versions.
- Added pull request contribution checks and release tooling documentation.
- Corrected package, repository, and SARIF release metadata.
- Improved public documentation for the built-in and optional Semgrep engines.

## 0.3.1 - 2026-08-29

- Published the CanoP CLI package to PyPI.
- Added multi-language security rules, JSON/SARIF output, and AI fix prescriptions.
