"""
CanoP Semgrep Engine
--------------------
Wraps Semgrep OSS as the primary scanning engine for AST-level analysis.
Falls back gracefully if Semgrep is not installed.
"""

import json
import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger("canop.semgrep")

# Path to bundled CanoP Semgrep rules
_RULES_DIR = Path(__file__).parent / "rules"


def is_semgrep_available() -> bool:
    """Check if Semgrep CLI is on PATH and executable."""
    return shutil.which("semgrep") is not None


def get_semgrep_version() -> Optional[str]:
    """Return the installed Semgrep version string, or None."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _build_finding_from_semgrep(result: dict, scan_root: str) -> dict:
    """
    Convert a single Semgrep JSON result into a CanoP Finding dict.

    Semgrep result structure (relevant fields):
      - check_id: str            (rule ID like "canop.python-injection.eval-usage")
      - path: str                (absolute or relative file path)
      - start: {line, col}
      - end: {line, col}
      - extra:
          - message: str
          - severity: str        ("ERROR", "WARNING", "INFO")
          - metadata: dict       (our custom metadata from the YAML rule)
          - lines: str           (matched source line)
    """
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})

    # Map Semgrep severities to CanoP severities
    _sev_map = {
        "ERROR": metadata.get("canop_severity", "HIGH"),
        "WARNING": metadata.get("canop_severity", "MEDIUM"),
        "INFO": metadata.get("canop_severity", "LOW"),
    }

    semgrep_sev = extra.get("severity", "WARNING")
    severity = _sev_map.get(semgrep_sev, metadata.get("canop_severity", "MEDIUM"))

    # Build relative path
    raw_path = result.get("path", "")
    try:
        rel_path = str(Path(raw_path).relative_to(Path(scan_root).resolve()))
    except ValueError:
        rel_path = raw_path

    # Build the CanoP finding
    check_id = result.get("check_id", "CANOP-SG-UNKNOWN")
    # Extract a short rule ID from the check_id (e.g. "canop.python-injection.eval-usage" -> "CANOP-SG-eval-usage")
    rule_short = check_id.split(".")[-1] if "." in check_id else check_id
    rule_id = f"CANOP-SG-{rule_short}".upper().replace("-", "-")

    return {
        "rule_id": rule_id,
        "path": rel_path.replace("\\", "/"),
        "line": result.get("start", {}).get("line", 0),
        "col": result.get("start", {}).get("col", 0),
        "severity": severity,
        "confidence": metadata.get("confidence", "HIGH"),
        "category": metadata.get("category", "security"),
        "message": extra.get("message", "Security issue detected by Semgrep"),
        "snippet": extra.get("lines", ""),
        "cwe": metadata.get("cwe", None),
        "fix_hint": metadata.get("fix", None),
        "prescription": metadata.get("prescription", None),
        "engine": "semgrep",
    }


def run_semgrep_scan(
    path: str,
    rules_dir: Optional[str] = None,
    languages: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run Semgrep with CanoP rules on the given path.

    Args:
        path: Directory or file to scan.
        rules_dir: Path to Semgrep YAML rules. Defaults to bundled rules.
        languages: Optional list of languages to filter (e.g. ["python"]).

    Returns:
        Dict with keys:
          - findings: list of Finding dicts
          - files_scanned: int
          - errors: list of error strings
          - engine: "semgrep"
    """
    if not is_semgrep_available():
        logger.info("Semgrep not found on PATH — skipping AST-based scan")
        return {
            "findings": [],
            "files_scanned": 0,
            "errors": ["semgrep_not_installed"],
            "engine": "semgrep",
        }

    rules_path = rules_dir or str(_RULES_DIR)

    # Check that rules directory exists and has YAML files
    rules_p = Path(rules_path)
    if not rules_p.exists() or not any(rules_p.glob("*.yml")):
        logger.warning("No Semgrep rules found at %s", rules_path)
        return {
            "findings": [],
            "files_scanned": 0,
            "errors": ["no_rules_found"],
            "engine": "semgrep",
        }

    scan_path = str(Path(path).resolve())

    cmd = [
        "semgrep",
        "--json",
        "--config", rules_path,
        "--no-git-ignore",  # We handle ignoring ourselves via .canopignore
        "--timeout", "30",  # Per-rule timeout
        "--max-target-bytes", "1048576",  # 1MB, same as regex engine
        "--quiet",  # Suppress banner/progress
    ]

    # Language filter
    if languages:
        for lang in languages:
            cmd.extend(["--lang", lang])

    cmd.append(scan_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute total timeout
            cwd=scan_path,
        )

        # Semgrep exits 0 on success (even with findings), 1 on errors
        output = result.stdout
        if not output:
            logger.debug("Semgrep produced no output (stderr: %s)", result.stderr[:500] if result.stderr else "")
            return {
                "findings": [],
                "files_scanned": 0,
                "errors": [result.stderr[:200]] if result.stderr else [],
                "engine": "semgrep",
            }

        data = json.loads(output)

    except subprocess.TimeoutExpired:
        logger.warning("Semgrep scan timed out after 300s")
        return {
            "findings": [],
            "files_scanned": 0,
            "errors": ["timeout"],
            "engine": "semgrep",
        }
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Semgrep output parsing failed: %s", exc)
        return {
            "findings": [],
            "files_scanned": 0,
            "errors": [str(exc)],
            "engine": "semgrep",
        }

    # Parse results
    findings = []
    raw_results = data.get("results", [])
    for r in raw_results:
        try:
            finding = _build_finding_from_semgrep(r, scan_path)
            findings.append(finding)
        except (KeyError, TypeError, ValueError) as exc:
            logger.debug("Skipping malformed Semgrep result: %s", exc)
            continue

    # Count scanned files from paths
    scanned_paths = data.get("paths", {})
    files_scanned = len(scanned_paths.get("scanned", []))

    # Collect errors
    errors_raw = data.get("errors", [])
    errors = [e.get("message", str(e))[:200] for e in errors_raw if isinstance(e, dict)]

    return {
        "findings": findings,
        "files_scanned": files_scanned,
        "errors": errors,
        "engine": "semgrep",
    }
