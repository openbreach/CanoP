"""
CanoP Static Analysis Scanner
------------------------------
Pattern-based security scanner targeting vulnerabilities commonly introduced
by AI code-generation tools (Copilot, ChatGPT, etc.).

Supports: Python, JavaScript/TypeScript, Java, Go, C#, Ruby, PHP
Output: structured findings list compatible with SARIF conversion.
"""

import os
import re
import time
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

logger = logging.getLogger("canop.scanner")

# ───────────────────────────── data models ──────────────────────────────

@dataclass
class Finding:
    rule_id: str
    path: str
    line: int
    col: int
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str        # HIGH | MEDIUM | LOW
    category: str          # e.g. "injection", "crypto", "secrets"
    message: str
    snippet: str = ""
    cwe: Optional[str] = None
    fix_hint: Optional[str] = None
    prescription: Optional[dict] = None

@dataclass
class ScanSummary:
    scan_id: str
    scanned_at: str
    path: str
    files_scanned: int
    lines_scanned: int
    duration_ms: int
    findings: List[Finding] = field(default_factory=list)
    severity_counts: dict = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    })

# ───────────────────────────── rule engine ──────────────────────────────
# All rules are defined in Semgrep YAML format in canop/rules/*.yml
# This loader reads them and converts to an internal format for execution.

_LANG_TO_EXT = {
    "python": {".py"},
    "javascript": {".js", ".jsx"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "ruby": {".rb"},
    "csharp": {".cs"},
    "php": {".php"},
    "html": {".html"},
    "json": {".json"},
    "yaml": {".yml", ".yaml"},
    "bash": {".sh", ".bash"},
    "generic": None,
}

_SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def _load_rules_from_yaml() -> list:
    """
    Load all Semgrep YAML rules from the bundled rules directory.
    Converts each rule with a `pattern-regex` field into an executable
    internal rule dict compatible with the scanning loop.
    """
    rules_dir = Path(__file__).parent / "rules"
    if not rules_dir.exists():
        logger.warning("Rules directory not found: %s", rules_dir)
        return []

    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed — cannot load YAML rules")
        return []

    rules = []
    for yml_file in sorted(rules_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if not data or "rules" not in data:
                continue
            for rule in data["rules"]:
                pattern = rule.get("pattern-regex")
                if not pattern:
                    continue  # AST-only patterns need Semgrep CLI

                # Map languages → file extensions
                langs = set()
                for lang in rule.get("languages", []):
                    exts = _LANG_TO_EXT.get(lang)
                    if exts:
                        langs.update(exts)
                    elif lang == "generic":
                        langs = None
                        break

                meta = rule.get("metadata", {})
                semgrep_sev = rule.get("severity", "WARNING")
                severity = meta.get("canop_severity", _SEV_MAP.get(semgrep_sev, "MEDIUM"))

                # Build a clean rule ID from the Semgrep check_id
                raw_id = rule.get("id", "unknown")
                parts = raw_id.split(".")
                short = parts[-1] if len(parts) > 1 else raw_id
                rule_id = f"CANOP-{short}".upper().replace("_", "-")

                msg = rule.get("message", "Security issue detected")
                # Collapse multi-line YAML messages
                if isinstance(msg, str):
                    msg = " ".join(msg.split())

                rules.append({
                    "id": rule_id,
                    "pattern": pattern,
                    "severity": severity,
                    "confidence": meta.get("confidence", "MEDIUM"),
                    "category": meta.get("category", "security"),
                    "langs": langs,
                    "message": msg,
                    "cwe": meta.get("cwe"),
                    "fix": meta.get("fix"),
                    "prescription": meta.get("prescription"),
                    "skip_in_strings": meta.get("skip_in_strings", True),
                })
        except Exception as exc:
            logger.debug("Failed to load %s: %s", yml_file.name, exc)

    logger.info("Loaded %d rules from %s", len(rules), rules_dir)
    return rules


# Load rules at module init — all rules are defined in canop/rules/*.yml
_RULES = _load_rules_from_yaml()

# ── File extensions to scan ────────────────────────────────────────────
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
    ".cs", ".php", ".html", ".env", ".yml", ".yaml", ".json",
    ".toml", ".cfg", ".ini", ".sh", ".bash",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "dist",
    "build", ".next", ".nuxt", "target", "bin", "obj",
    ".idea", ".vscode", "vendor",
}

MAX_FILE_SIZE = 1_048_576  # 1 MB — skip huge generated files

# ───────────────────────────── .canopignore ────────────────────────────

def _load_ignore_patterns(scan_root: Path) -> list:
    """
    Load glob patterns from .canopignore (same syntax as .gitignore).
    Returns a list of compiled patterns.
    """
    ignore_file = scan_root / ".canopignore"
    patterns = []
    if ignore_file.exists():
        try:
            for raw_line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
        except OSError:
            pass
    return patterns


def _is_ignored(rel_path: str, patterns: list) -> bool:
    """Check if a relative path matches any .canopignore pattern."""
    from fnmatch import fnmatch
    rel_posix = rel_path.replace("\\", "/")
    for pat in patterns:
        if fnmatch(rel_posix, pat) or fnmatch(rel_posix, f"**/{pat}"):
            return True
        # Also check if any path component matches a directory pattern
        if pat.endswith("/") and any(fnmatch(part, pat.rstrip("/")) for part in rel_posix.split("/")):
            return True
    return False


# ───────────────────────────── inline ignore ───────────────────────────

_IGNORE_MARKER = re.compile(r"canop:\s*ignore", re.IGNORECASE)


def _line_has_ignore_marker(line: str) -> bool:
    """Check if a line contains `# canop:ignore` or `// canop:ignore`."""
    return bool(_IGNORE_MARKER.search(line))


# ───────────────────────────── git diff ────────────────────────────────

def _get_changed_files(scan_root: Path) -> Optional[set]:
    """
    Return the set of files changed relative to HEAD (staged + unstaged + untracked).
    Returns None if not a git repo or git is unavailable.
    """
    import subprocess as _sp
    try:
        # Changed (staged + unstaged)
        diff_out = _sp.check_output(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=str(scan_root),
            stderr=_sp.DEVNULL,
            text=True,
        )
        # Untracked files
        untracked_out = _sp.check_output(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=str(scan_root),
            stderr=_sp.DEVNULL,
            text=True,
        )
        files = set()
        for line in (diff_out + untracked_out).strip().splitlines():
            if line.strip():
                files.add(line.strip().replace("/", os.sep))
        return files
    except (OSError, FileNotFoundError, ValueError):
        return None


# ───────────────────────────── security score ──────────────────────────

_SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

def calculate_security_score(findings: list, lines_scanned: int) -> dict:
    """
    Calculate a security score (0-100) and letter grade (A+ to F).
    
    Formula:
      penalty = sum(severity_weight * count)
      score = max(0, 100 - penalty)
    
    Weights: CRITICAL=25, HIGH=10, MEDIUM=4, LOW=1, INFO=0
    
    Grades:
      A+ = 100, A = 90-99, B = 80-89, C = 65-79, D = 50-64, F = 0-49
    
    If any CRITICAL exists, score is capped at 49 (F).
    """
    if not findings:
        return {"score": 100, "grade": "A+"}

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'INFO')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    penalty = sum(
        _SEVERITY_WEIGHTS.get(sev, 0) * count
        for sev, count in severity_counts.items()
    )
    score = max(0, 100 - penalty)

    # CRITICAL findings cap the score at F
    if severity_counts.get("CRITICAL", 0) > 0:
        score = min(score, 49)

    # Grade mapping
    if score == 100:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade}

# ───────────────────────────── scanner ─────────────────────────────────

def _is_comment(line: str, ext: str) -> bool:
    """
    Detect whether a line is a comment (single-line only).
    Returns True for obvious comment lines to reduce false positives.
    Does NOT detect inline comments or multi-line block comments —
    those are handled by _match_is_in_string for most practical cases.
    """
    stripped = line.lstrip()
    if not stripped:
        return True  # blank lines produce no findings anyway
    if ext in {".py", ".rb", ".sh", ".bash", ".yml", ".yaml", ".toml", ".cfg", ".ini"}:
        return stripped.startswith("#")
    if ext in {".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cs", ".php"}:
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    if ext == ".html":
        return stripped.startswith("<!--")
    return False


def _match_is_in_string(line: str, match_start: int, ext: str = "") -> bool:
    """
    Heuristic: check whether `match_start` falls inside a string literal
    (single-quoted, double-quoted, or backtick template literal).
    Handles escaped quotes.

    This prevents false positives from lines like:
        print("eval() is dangerous")
        console.log("password reset sent")
        msg = "never use os.system()"
    """
    in_single = False
    in_double = False
    in_backtick = False
    i = 0
    while i < match_start and i < len(line):
        ch = line[i]
        if ch == '\\' and not in_backtick:
            i += 2  # skip escaped character
            continue
        if ch == '`':
            in_backtick = not in_backtick
        elif ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
        elif ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
        i += 1
    return in_single or in_double or in_backtick


def _get_snippet(lines: list, line_idx: int, context: int = 1) -> str:
    """Return the line plus surrounding context lines."""
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    return "\n".join(lines[start:end])


# ─────────────────────── language breakdown helper ─────────────────────

_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rb": "ruby",
    ".cs": "csharp", ".php": "php", ".html": "html",
}


def _count_language_breakdown(findings_list: list) -> Dict[str, int]:
    """Count findings per language based on file extension."""
    breakdown: Dict[str, int] = {}
    for f in findings_list:
        fp = f.get("path", "") if isinstance(f, dict) else f.path
        ext = Path(fp).suffix.lower()
        lang = _EXT_TO_LANG.get(ext, "other")
        breakdown[lang] = breakdown.get(lang, 0) + 1
    return breakdown


def run_scan(path: str, changed_only: bool = False, on_file: callable = None) -> dict:
    """
    Scan the directory tree at `path` for security vulnerabilities.
    Returns a dict with `scan_id`, `summary`, `findings`, and `security_score`.

    Engine strategy:
      1. Try Semgrep (AST-level) for Python files if available.
      2. Always run regex engine as fallback / for non-Python languages.
      3. Merge and deduplicate results.

    Args:
        path: Directory to scan.
        changed_only: If True, only scan files changed in git.
        on_file: Optional callback(file_path) called for each file scanned (for progress).
    """
    t0 = time.perf_counter()
    path_obj = Path(path).resolve()

    findings: List[Finding] = []
    files_scanned = 0
    lines_scanned = 0
    files_skipped_ignore = 0
    engine_used = "semgrep"  # default; upgraded to semgrep+ast if Semgrep CLI runs

    # ── Phase 1: Semgrep scan (Python-focused, AST-level) ──────────────
    semgrep_finding_keys = set()  # track (path, line) pairs from Semgrep to avoid dupes
    try:
        from canop.semgrep_engine import is_semgrep_available, run_semgrep_scan

        if is_semgrep_available():
            logger.info("Semgrep detected — running AST-level scan")
            sg_result = run_semgrep_scan(str(path_obj))

            if sg_result["findings"]:
                engine_used = "semgrep+ast"  # full AST + pattern engine
                for sg_finding in sg_result["findings"]:
                    f = Finding(
                        rule_id=sg_finding["rule_id"],
                        path=sg_finding["path"],
                        line=sg_finding["line"],
                        col=sg_finding.get("col", 1),
                        severity=sg_finding["severity"],
                        confidence=sg_finding.get("confidence", "HIGH"),
                        category=sg_finding.get("category", "security"),
                        message=sg_finding["message"],
                        snippet=sg_finding.get("snippet", ""),
                        cwe=sg_finding.get("cwe"),
                        fix_hint=sg_finding.get("fix_hint"),
                        prescription=sg_finding.get("prescription"),
                    )
                    findings.append(f)
                    semgrep_finding_keys.add((f.path, f.line))
            elif not sg_result["errors"]:
                engine_used = "semgrep+ast"  # ran successfully, just no findings
        else:
            logger.info("Semgrep CLI not installed — using built-in pattern engine")
    except ImportError:
        logger.debug("semgrep_engine module not available")
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("Semgrep AST scan failed, falling back to pattern engine: %s", exc)

    # ── Phase 2: Pattern scan (all languages, built-in engine) ───────────
    # Load .canopignore patterns
    ignore_patterns = _load_ignore_patterns(path_obj)

    # Git diff mode
    changed_files = None
    if changed_only:
        changed_files = _get_changed_files(path_obj)

    compiled_rules = []
    for rule in _RULES:
        try:
            compiled_rules.append({
                **rule,
                "_re": re.compile(rule["pattern"]),
            })
        except re.error:
            continue  # skip malformed patterns

    for root, dirs, files in os.walk(path_obj):
        # prune skippable directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCANNABLE_EXTENSIONS:
                continue

            fpath = Path(root) / fname
            rel_path = str(fpath.relative_to(path_obj))

            # .canopignore check
            if ignore_patterns and _is_ignored(rel_path, ignore_patterns):
                files_skipped_ignore += 1
                continue

            # Git diff filter
            if changed_files is not None and rel_path not in changed_files:
                continue

            # skip large files
            try:
                if fpath.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                raw = fpath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            file_lines = raw.splitlines()
            files_scanned += 1
            lines_scanned += len(file_lines)

            # Progress callback
            if on_file:
                on_file(rel_path)

            for rule in compiled_rules:
                # language filter
                if rule["langs"] is not None and ext not in rule["langs"]:
                    continue

                for idx, line in enumerate(file_lines, start=1):
                    if _is_comment(line, ext):
                        continue

                    # Inline canop:ignore support
                    if _line_has_ignore_marker(line):
                        continue

                    m = rule["_re"].search(line)
                    if m:
                        # Skip false positives: pattern matched inside a
                        # string literal (e.g. print("eval() is bad"))
                        if rule.get("skip_in_strings", True) and \
                                _match_is_in_string(line, m.start(), ext):
                            continue

                        # Skip if Semgrep already found something at this location
                        norm_path = rel_path.replace("\\", "/")
                        if (norm_path, idx) in semgrep_finding_keys:
                            continue

                        findings.append(Finding(
                            rule_id=rule["id"],
                            path=rel_path,
                            line=idx,
                            col=m.start() + 1,
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            category=rule["category"],
                            message=rule["message"],
                            snippet=_get_snippet(file_lines, idx - 1),
                            cwe=rule.get("cwe"),
                            fix_hint=rule.get("fix"),
                            prescription=rule.get("prescription"),
                        ))

    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    # Deduplicate: same rule + same file + same line
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    # Sort by severity weight
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.path, f.line))

    # Build severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    # Deterministic scan ID
    scan_id = hashlib.sha256(
        f"{path_obj}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12]

    summary = ScanSummary(
        scan_id=scan_id,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        path=str(path_obj),
        files_scanned=files_scanned,
        lines_scanned=lines_scanned,
        duration_ms=elapsed_ms,
        findings=findings,
        severity_counts=severity_counts,
    )

    # Calculate security score
    score_info = calculate_security_score(findings, lines_scanned)

    # Language breakdown
    findings_dicts = [asdict(f) for f in findings]
    language_breakdown = _count_language_breakdown(findings_dicts)

    # Count rules and categories for display
    rules_loaded = len(compiled_rules)
    categories = set()
    for r in compiled_rules:
        categories.add(r.get("category", "security"))

    return {
        "scan_id": summary.scan_id,
        "scanned_at": summary.scanned_at,
        "path": summary.path,
        "files_scanned": summary.files_scanned,
        "lines_scanned": summary.lines_scanned,
        "duration_ms": summary.duration_ms,
        "severity_counts": summary.severity_counts,
        "findings": findings_dicts,
        "security_score": score_info["score"],
        "security_grade": score_info["grade"],
        "changed_only": changed_only,
        "files_skipped_ignore": files_skipped_ignore,
        "engine": engine_used,
        "rules_loaded": rules_loaded,
        "category_count": len(categories),
        "language_breakdown": language_breakdown,
    }


def export_sarif(scan_result: dict) -> dict:
    """Convert scan results to SARIF v2.1.0 format for CI/CD integration."""
    rules = {}
    results = []

    for f in scan_result["findings"]:
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": f["message"]},
                "properties": {"severity": f["severity"]},
            }
            if f.get("cwe"):
                rules[rid]["relationships"] = [{
                    "target": {"id": f["cwe"], "toolComponent": {"name": "CWE"}},
                    "kinds": ["superset"],
                }]

        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

        results.append({
            "ruleId": rid,
            "level": level_map.get(f["severity"], "warning"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["path"]},
                    "region": {"startLine": f["line"], "startColumn": f["col"]},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CanoP",
                    "version": "0.3.0",
                    "informationUri": "https://canop.dev",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
