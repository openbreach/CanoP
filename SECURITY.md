# Security Policy

## Supported Versions

Currently, the `main` branch of CanoP is actively supported with security updates. 

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in the CanoP CLI that could compromise user data, please report it via email directly to the maintainers (or through GitHub Security Advisories if enabled on this repo).

Please include:
*   The type of vulnerability (e.g., path traversal, arbitrary code execution in the CLI).
*   Step-by-step instructions to reproduce the vulnerability.
*   (Optional) Any suggestions on how to fix it.

We aim to acknowledge reports within 48 hours and patch critical vulnerabilities as our top priority.

### Scope

*   **In Scope:** Vulnerabilities in the CanoP engine, internal parsers, or CLI logic.
*   **Out of Scope:** False positives or false negatives in the YAML rules. If a rule misses a vulnerability (false negative) or flags secure code (false positive), please open a standard GitHub Issue or submit a Pull Request to fix the YAML pattern.