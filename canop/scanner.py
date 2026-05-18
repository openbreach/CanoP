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
# Rules are defined in Semgrep YAML format in canop/rules/*.yml
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


# Load rules at module init — called once on import
_DEFAULT_RULES = [
    {
        "id": "CANOP-INJ-001",
        "pattern": r"\beval\s*\(",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "injection",
        "langs": {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php"},
        "message": "Use of eval() allows arbitrary code execution",
        "cwe": "CWE-95",
        "fix": "Replace eval() with ast.literal_eval() (Python) or JSON.parse() (JS)",
        "prescription": {
            "task": "Eliminate arbitrary code execution via eval()",
            "vulnerability": "eval() interprets a string as code at runtime, allowing an attacker who controls the input to execute arbitrary commands",
            "fix_strategy": "Replace eval() with a type-safe parser that only handles the data type you expect",
            "fix_patterns": {
                "python": "import ast; result = ast.literal_eval(user_input)  # only parses Python literals (str, int, list, dict, etc.)",
                "javascript": "const result = JSON.parse(userInput);  // only parses JSON, no code execution",
                "ruby": "result = JSON.parse(user_input)  # or use a safe DSL parser",
                "php": "json_decode($userInput, true);  // never use eval() on user input"
            },
            "constraints": [
                "Do NOT pass any user-controlled or external input to eval()",
                "If parsing config, use JSON, YAML (safe_load), or TOML parsers",
                "If computing math expressions, use a sandboxed math parser (e.g. asteval for Python, mathjs for JS)",
                "Audit all call sites — eval() hidden in utility functions is still dangerous"
            ],
            "test_after": "Attempt input: __import__('os').system('echo pwned') — must raise an error, not execute"
        }
    },
    {
        "id": "CANOP-INJ-002",
        "pattern": r"\bexec\s*\(",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "injection",
        "langs": {".py"},
        "message": "Use of exec() allows arbitrary code execution",
        "cwe": "CWE-95",
        "fix": "Avoid exec(); use safe alternatives or sandboxed execution",
        "prescription": {
            "task": "Remove arbitrary code execution via exec()",
            "vulnerability": "exec() runs a string as Python code at runtime, giving full interpreter access to anyone who controls the input",
            "fix_strategy": "Replace exec() with structured logic (if/elif dispatch, dict lookup, or importlib for dynamic loading)",
            "fix_patterns": {
                "python": "# Instead of exec(f'func_{name}()'):\nhandlers = {'a': func_a, 'b': func_b}\nhandlers[name]()"
            },
            "constraints": [
                "Never pass user-controlled strings to exec()",
                "If you need dynamic dispatch, use a dict of callables or getattr() on a known object",
                "If templating, use Jinja2 sandboxed environment instead of exec()",
                "Remove exec() entirely — there is almost always a safer pattern"
            ],
            "test_after": "Verify no user/external input can reach exec(); grep for exec( across the codebase to confirm removal"
        }
    },
    {
        "id": "CANOP-INJ-003",
        "pattern": r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "injection",
        "langs": {".py"},
        "message": "Shell injection risk via subprocess with shell=True",
        "cwe": "CWE-78",
        "fix": "Use shell=False and pass args as a list",
        "prescription": {
            "task": "Fix shell injection in subprocess call",
            "vulnerability": "shell=True passes the command through the system shell, allowing injection via metacharacters (;, |, &&, $()) in user input",
            "fix_strategy": "Set shell=False and pass the command as a list of arguments. Sanitize any user-provided values with shlex.quote()",
            "fix_patterns": {
                "python": "import shlex, subprocess\nsubprocess.run(['ping', '-c', '1', shlex.quote(user_host)], shell=False, check=True, capture_output=True)"
            },
            "constraints": [
                "Set shell=False (or omit it — False is the default)",
                "Pass command and arguments as a list: ['cmd', 'arg1', 'arg2']",
                "Wrap any user-provided argument with shlex.quote()",
                "Validate user input format (e.g. regex for expected hostname/IP) before execution",
                "Use capture_output=True to avoid leaking command output"
            ],
            "test_after": "Attempt input containing: ; rm -rf / — must be passed as a literal string argument, not interpreted by shell"
        }
    },
    {
        "id": "CANOP-INJ-004",
        "pattern": r"os\.system\s*\(",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "injection",
        "langs": {".py"},
        "message": "os.system() is vulnerable to shell injection",
        "cwe": "CWE-78",
        "fix": "Use subprocess.run() with shell=False",
        "prescription": {
            "task": "Replace os.system() with safe subprocess call",
            "vulnerability": "os.system() always invokes the system shell, making it trivially exploitable if any part of the command string is user-controlled",
            "fix_strategy": "Replace with subprocess.run() using a list of arguments and shell=False",
            "fix_patterns": {
                "python": "import subprocess\n# Before: os.system(f'ls {directory}')\n# After:\nsubprocess.run(['ls', directory], shell=False, check=True)"
            },
            "constraints": [
                "Replace ALL os.system() calls — there is no safe way to use it with dynamic input",
                "Never construct the command string with f-strings, .format(), or + concatenation",
                "Use subprocess.run() with list arguments for full control"
            ],
            "test_after": "Search for os.system( — should return zero results. Test with input containing shell metacharacters"
        }
    },
    {
        "id": "CANOP-INJ-005",
        "pattern": r"child_process\.(exec|execSync)\s*\(",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "injection",
        "langs": {".js", ".ts"},
        "message": "child_process.exec() is vulnerable to command injection",
        "cwe": "CWE-78",
        "fix": "Use child_process.execFile() or spawn() with args array",
        "prescription": {
            "task": "Fix command injection in child_process.exec()",
            "vulnerability": "exec()/execSync() run commands through the system shell, allowing injection via user-controlled input containing shell metacharacters",
            "fix_strategy": "Replace with execFile() or spawn() which bypass the shell and take arguments as an array",
            "fix_patterns": {
                "javascript": "const { execFile } = require('child_process');\n// Before: exec(`ping ${host}`);\n// After:\nexecFile('ping', ['-c', '1', host], (err, stdout) => { });"
            },
            "constraints": [
                "Use execFile() or spawn() instead of exec()/execSync()",
                "Pass arguments as an array, never as part of the command string",
                "Validate user input before passing to any command",
                "Never use template literals to build command strings"
            ],
            "test_after": "Attempt input: $(whoami) or ; cat /etc/passwd — must be treated as literal arguments"
        }
    },
    {
        "id": "CANOP-INJ-006",
        "pattern": r"os\.popen\s*\(",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "injection",
        "langs": {".py"},
        "message": "os.popen() is vulnerable to shell injection",
        "cwe": "CWE-78",
        "fix": "Use subprocess.run() with shell=False",
        "prescription": {
            "task": "Replace os.popen() with safe subprocess call",
            "vulnerability": "os.popen() invokes the system shell to run the command, enabling injection if any portion is user-controlled",
            "fix_strategy": "Replace with subprocess.run() using list arguments and shell=False, and capture output via capture_output=True",
            "fix_patterns": {
                "python": "import subprocess\n# Before: output = os.popen(f'whoami').read()\n# After:\nresult = subprocess.run(['whoami'], capture_output=True, text=True, shell=False)\noutput = result.stdout"
            },
            "constraints": [
                "Replace ALL os.popen() calls with subprocess.run()",
                "Use capture_output=True to get stdout/stderr",
                "Pass command as a list, not a string"
            ],
            "test_after": "Grep for os.popen( — should return zero results"
        }
    },
    # ── SQL Injection ──────────────────────────────────────────────────
    {
        "id": "CANOP-SQL-001",
        "pattern": r"""(?:f['"]|\.format\s*\().*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b""",
        "severity": "CRITICAL",
        "confidence": "MEDIUM",
        "category": "sql-injection",
        "langs": {".py"},
        "message": "Possible SQL injection via string formatting",
        "cwe": "CWE-89",
        "fix": "Use parameterized queries or ORM methods",
        "skip_in_strings": False,
        "prescription": {
            "task": "Fix SQL injection via string formatting",
            "vulnerability": "SQL query built using f-strings or .format() embeds user input directly into the query, allowing an attacker to modify the SQL logic",
            "fix_strategy": "Use parameterized queries (placeholders) so the database driver handles escaping. Or use an ORM.",
            "fix_patterns": {
                "python_sqlite": "cursor.execute('SELECT * FROM users WHERE email = ?', (email,))",
                "python_psycopg2": "cursor.execute('SELECT * FROM users WHERE email = %s', (email,))",
                "python_sqlalchemy": "db.session.query(User).filter(User.email == email).first()"
            },
            "constraints": [
                "NEVER use f-strings, .format(), or % formatting to build SQL queries",
                "Use ? (sqlite3) or %s (psycopg2/mysql) placeholders",
                "Use ORM methods (SQLAlchemy, Django ORM) which parameterize by default",
                "If raw SQL is required for performance, use text() with bindparams in SQLAlchemy"
            ],
            "test_after": "Attempt input: ' OR 1=1 -- in any user-facing input that touches SQL — must not alter query logic"
        }
    },
    {
        "id": "CANOP-SQL-002",
        "pattern": r"""\$\{[^}]*\}.*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b|\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\$\{[^}]*\}""",
        "severity": "CRITICAL",
        "confidence": "MEDIUM",
        "category": "sql-injection",
        "langs": {".js", ".ts", ".jsx", ".tsx"},
        "message": "Possible SQL injection via template literal interpolation",
        "cwe": "CWE-89",
        "fix": "Use parameterized queries (e.g. $1 placeholders)",
        "skip_in_strings": False,
        "prescription": {
            "task": "Fix SQL injection via JS template literals",
            "vulnerability": "Template literal interpolation (${var}) in SQL strings embeds user input directly, enabling SQL injection",
            "fix_strategy": "Use parameterized queries with positional placeholders ($1, $2) and pass values as a separate array",
            "fix_patterns": {
                "javascript_pg": "await pool.query('SELECT * FROM users WHERE email = $1', [email]);",
                "javascript_mysql": "await connection.execute('SELECT * FROM users WHERE email = ?', [email]);",
                "javascript_knex": "await knex('users').where({ email }).first();"
            },
            "constraints": [
                "NEVER use template literals (backticks) to interpolate values into SQL",
                "Use $1, $2 placeholders (pg) or ? placeholders (mysql2) with parameter arrays",
                "Use a query builder (Knex, Prisma, Drizzle) that parameterizes automatically",
                "Audit all database query calls for string interpolation"
            ],
            "test_after": "Attempt input: '; DROP TABLE users; -- — must be treated as a string value, not SQL"
        }
    },
    {
        "id": "CANOP-SQL-003",
        "pattern": r"""['\"].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*['\"].*\+\s*\w+|\w+\s*\+\s*['\"].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b""",
        "severity": "CRITICAL",
        "confidence": "MEDIUM",
        "category": "sql-injection",
        "langs": {".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".php"},
        "message": "Possible SQL injection via string concatenation",
        "cwe": "CWE-89",
        "fix": "Use parameterized queries instead of string concatenation",
        "skip_in_strings": False,
        "prescription": {
            "task": "Fix SQL injection via string concatenation",
            "vulnerability": "SQL query built by concatenating strings with + operator allows user input to modify query structure",
            "fix_strategy": "Replace string concatenation with parameterized queries using your language's database driver",
            "fix_patterns": {
                "java": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE email = ?\");\nps.setString(1, email);",
                "csharp": "using var cmd = new SqlCommand(\"SELECT * FROM users WHERE email = @email\", conn);\ncmd.Parameters.AddWithValue(\"@email\", email);",
                "php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');\n$stmt->execute(['email' => $email]);"
            },
            "constraints": [
                "NEVER concatenate user input into SQL with + operator",
                "Use PreparedStatement (Java), SqlParameter (C#), or PDO prepared statements (PHP)",
                "All user input in WHERE, INSERT VALUES, and ORDER BY must use placeholders"
            ],
            "test_after": "Attempt input: ' UNION SELECT * FROM admin -- — query must not return admin data"
        }
    },
    # ── Secrets / Credentials ──────────────────────────────────────────
    {
        "id": "CANOP-SEC-001",
        "pattern": r"""(?i)^[^#/]*\b(password|passwd|secret|api_key|apikey|access_token|private_key|auth_token|secret_key)\s*=\s*['\"][^'\"]{4,}['\"]""",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "category": "secrets",
        "langs": {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".cs", ".php"},
        "message": "Potential hardcoded credential or secret",
        "cwe": "CWE-798",
        "fix": "Move secrets to environment variables or a secret manager",
        "skip_in_strings": False,
        "prescription": {
            "task": "Remove hardcoded credential from source code",
            "vulnerability": "Secret value is hardcoded in source code, meaning it will be committed to version control and visible to anyone with repo access",
            "fix_strategy": "Move the secret to an environment variable and read it at runtime. Never commit real credentials.",
            "fix_patterns": {
                "python": "import os\nAPI_KEY = os.environ['API_KEY']  # set in .env or deployment config",
                "javascript": "const API_KEY = process.env.API_KEY;",
                "go": "apiKey := os.Getenv(\"API_KEY\")"
            },
            "constraints": [
                "Remove the hardcoded value from the source file",
                "Add a .env.example file with placeholder values (API_KEY=your_key_here)",
                "Add .env to .gitignore to prevent accidental commits",
                "Use a secret manager (AWS Secrets Manager, Vault, Doppler) in production",
                "If this secret was already committed, rotate it immediately — git history retains it"
            ],
            "test_after": "Grep the codebase for the old secret value — should return zero matches. Verify app reads from env var correctly."
        }
    },
    {
        "id": "CANOP-SEC-002",
        "pattern": r"""AKIA[0-9A-Z]{16}""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "secrets",
        "langs": None,
        "message": "AWS Access Key ID detected",
        "cwe": "CWE-798",
        "fix": "Remove and rotate the key immediately; use IAM roles or env vars",
        "skip_in_strings": False,
        "prescription": {
            "task": "Remove and rotate leaked AWS Access Key",
            "vulnerability": "AWS Access Key ID (AKIA...) found in source code. If committed to a public repo, automated bots will find and exploit it within minutes",
            "fix_strategy": "1) Immediately rotate the key in AWS IAM. 2) Remove from source. 3) Use IAM roles for EC2/Lambda or env vars for local dev.",
            "fix_patterns": {
                "python": "import boto3\n# boto3 automatically reads AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from environment\nclient = boto3.client('s3')  # no hardcoded credentials"
            },
            "constraints": [
                "IMMEDIATELY deactivate and rotate this key in AWS IAM console",
                "Check AWS CloudTrail for unauthorized usage of the exposed key",
                "Remove the key from ALL files in the repository",
                "Use git filter-branch or BFG Repo-Cleaner to purge from git history",
                "Use IAM Roles (EC2/ECS/Lambda) or environment variables — never hardcode"
            ],
            "test_after": "Run: grep -r 'AKIA' . — must return zero results. Verify AWS_ACCESS_KEY_ID env var is set in deployment."
        }
    },
    {
        "id": "CANOP-SEC-003",
        "pattern": r"""ghp_[0-9a-zA-Z]{36}""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "secrets",
        "langs": None,
        "message": "GitHub personal access token detected",
        "cwe": "CWE-798",
        "fix": "Revoke the token and use environment variables",
        "skip_in_strings": False,
        "prescription": {
            "task": "Remove and revoke leaked GitHub token",
            "vulnerability": "GitHub personal access token (ghp_...) in source code. GitHub auto-revokes tokens found in public repos, but private repos are still at risk",
            "fix_strategy": "Revoke the token at github.com/settings/tokens, generate a new one, and store it as an environment variable",
            "fix_patterns": {
                "any": "GITHUB_TOKEN=ghp_... in .env (git-ignored), read via os.environ['GITHUB_TOKEN'] or process.env.GITHUB_TOKEN"
            },
            "constraints": [
                "Revoke the exposed token immediately at GitHub Settings > Developer settings > Tokens",
                "Generate a new token with minimal required scopes",
                "Store in environment variable or secret manager",
                "Add .env to .gitignore"
            ],
            "test_after": "Run: grep -r 'ghp_' . — must return zero results"
        }
    },
    {
        "id": "CANOP-SEC-004",
        "pattern": r"""-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "secrets",
        "langs": None,
        "message": "Private key embedded in source code",
        "cwe": "CWE-321",
        "fix": "Store private keys in a secure vault or file outside the repository",
        "skip_in_strings": False,
        "prescription": {
            "task": "Remove private key from source code",
            "vulnerability": "Private key material committed to source code. Anyone with repo access can impersonate the key owner, decrypt data, or sign tokens",
            "fix_strategy": "Move the key to a secure location outside the repo (file system path, secret manager, or HSM) and reference it by path or environment variable",
            "fix_patterns": {
                "python": "from pathlib import Path\nPRIVATE_KEY = Path(os.environ['PRIVATE_KEY_PATH']).read_text()",
                "javascript": "const fs = require('fs');\nconst privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8');"
            },
            "constraints": [
                "Remove the key from ALL source files immediately",
                "Generate a NEW key pair — the exposed private key must be considered compromised",
                "Store the new key file outside the repository with 600 permissions (owner-only read)",
                "Use BFG Repo-Cleaner to purge from git history",
                "In production, use a secret manager (AWS KMS, Vault, GCP Secret Manager)"
            ],
            "test_after": "Run: grep -r 'BEGIN.*PRIVATE KEY' . — must return zero results"
        }
    },
    {
        "id": "CANOP-SEC-005",
        "pattern": r"""(?i)^(?:export\s+)?(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD|API_SECRET|JWT_SECRET|ENCRYPTION_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "secrets",
        "langs": {".env", ".sh", ".bash"},
        "message": "Secret value in environment/shell file — do not commit to version control",
        "cwe": "CWE-798",
        "fix": "Add this file to .gitignore and use a secret manager in production",
        "skip_in_strings": False,
        "prescription": {
            "task": "Prevent env file with secrets from being committed",
            "vulnerability": "Environment file containing secrets (passwords, API keys) is tracked in version control, exposing them to anyone with repo access",
            "fix_strategy": "Add the env file to .gitignore, create a .env.example with placeholder values, and use a secret manager for production",
            "fix_patterns": {
                "gitignore": "# Add to .gitignore:\n.env\n.env.local\n.env.production",
                "env_example": "# .env.example (commit this instead):\nDB_PASSWORD=your_database_password_here\nJWT_SECRET=generate_with_openssl_rand_hex_32"
            },
            "constraints": [
                "Add .env to .gitignore immediately",
                "Remove tracked .env from git: git rm --cached .env",
                "Create .env.example with placeholder values for onboarding",
                "Rotate ALL secrets that were in the committed .env file",
                "Use a secret manager in production (never deploy with .env files)"
            ],
            "test_after": "Run: git ls-files | grep '\\.env$' — must return nothing"
        }
    },
    {
        "id": "CANOP-SEC-006",
        "pattern": r"""(?i)sk[_-](?:live|test)[_-][0-9a-zA-Z]{24,}""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "secrets",
        "langs": None,
        "message": "Stripe API key detected",
        "cwe": "CWE-798",
        "fix": "Revoke and rotate the key; use environment variables",
        "skip_in_strings": False,
        "prescription": {
            "task": "Remove and rotate leaked Stripe API key",
            "vulnerability": "Stripe secret key (sk_live_... or sk_test_...) in source code. A live key allows anyone to create charges, refunds, and access customer data",
            "fix_strategy": "Roll the key in Stripe Dashboard > Developers > API keys, then store the new key as an environment variable",
            "fix_patterns": {
                "python": "import stripe\nstripe.api_key = os.environ['STRIPE_SECRET_KEY']",
                "javascript": "const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);"
            },
            "constraints": [
                "IMMEDIATELY roll the key in Stripe Dashboard (this invalidates the old key)",
                "Check Stripe Dashboard > Events for unauthorized activity",
                "Store new key in environment variable STRIPE_SECRET_KEY",
                "Use restricted keys with minimal permissions where possible"
            ],
            "test_after": "Run: grep -ri 'sk_live_\\|sk_test_' . — must return zero results"
        }
    },
    {
        "id": "CANOP-SEC-007",
        "pattern": r"""(?i)(?:SG\.)[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "secrets",
        "langs": None,
        "message": "SendGrid API key detected",
        "cwe": "CWE-798",
        "fix": "Revoke and rotate the key; use environment variables",
        "skip_in_strings": False,
        "prescription": {
            "task": "Remove and rotate leaked SendGrid API key",
            "vulnerability": "SendGrid API key (SG.xxx) in source code. An attacker can send email as your domain, potentially for phishing",
            "fix_strategy": "Delete the key in SendGrid Dashboard > Settings > API Keys, create a new one, store as environment variable",
            "fix_patterns": {
                "python": "import os\nSENDGRID_API_KEY = os.environ['SENDGRID_API_KEY']",
                "javascript": "const sgMail = require('@sendgrid/mail');\nsgMail.setApiKey(process.env.SENDGRID_API_KEY);"
            },
            "constraints": [
                "Delete the exposed key in SendGrid Dashboard immediately",
                "Create a new key with minimal permissions (Mail Send only if possible)",
                "Store in environment variable or secret manager",
                "Check SendGrid activity for unauthorized email sends"
            ],
            "test_after": "Run: grep -ri 'SG\\.' . | grep -v node_modules — verify no API keys in source"
        }
    },
    # ── Cryptography ───────────────────────────────────────────────────
    {
        "id": "CANOP-CRY-001",
        "pattern": r"""\b(?:md5|MD5)\s*\(""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "crypto",
        "langs": {".py", ".js", ".ts", ".java", ".go", ".php", ".rb"},
        "message": "MD5 is cryptographically broken; do not use for security purposes",
        "cwe": "CWE-327",
        "fix": "Use SHA-256+ for integrity checks or bcrypt/argon2 for passwords",
        "prescription": {
            "task": "Replace MD5 with a secure hash function",
            "vulnerability": "MD5 is cryptographically broken — collision attacks are practical and it should never be used for passwords, signatures, or integrity verification",
            "fix_strategy": "For passwords use bcrypt/argon2. For integrity checks use SHA-256. For non-security hashing (cache keys) MD5 is acceptable but annotate it.",
            "fix_patterns": {
                "python_password": "from passlib.hash import bcrypt\nhashed = bcrypt.hash(password)\nassert bcrypt.verify(password, hashed)",
                "python_integrity": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()",
                "javascript": "const crypto = require('crypto');\nconst hash = crypto.createHash('sha256').update(data).digest('hex');"
            },
            "constraints": [
                "If hashing passwords: use bcrypt, argon2, or scrypt — NEVER a raw hash function",
                "If verifying file integrity: use SHA-256 at minimum",
                "If used for non-security purposes (cache key, dedup): add a comment explaining why MD5 is acceptable here",
                "Search for all MD5 usage in the codebase — fix them all"
            ],
            "test_after": "Grep for md5\\|MD5 — all remaining uses should have explicit comments justifying non-security use"
        }
    },
    {
        "id": "CANOP-CRY-002",
        "pattern": r"""\b(?:sha1|SHA1)\s*\(""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "crypto",
        "langs": {".py", ".js", ".ts", ".java", ".go", ".php"},
        "message": "SHA-1 is deprecated for security use",
        "cwe": "CWE-327",
        "fix": "Use SHA-256 or stronger",
        "prescription": {
            "task": "Replace SHA-1 with SHA-256 or stronger",
            "vulnerability": "SHA-1 has known collision vulnerabilities (SHAttered attack, 2017). It is deprecated by NIST and browsers no longer accept SHA-1 certificates",
            "fix_strategy": "Replace with SHA-256 for integrity/hashing or bcrypt/argon2 for passwords",
            "fix_patterns": {
                "python": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()  # was: hashlib.sha1()",
                "javascript": "const hash = crypto.createHash('sha256').update(data).digest('hex');  // was: sha1"
            },
            "constraints": [
                "Replace sha1 with sha256 in all security contexts",
                "If used for git commit hashes or legacy compatibility, document the exception",
                "For password hashing, use bcrypt/argon2 instead of any SHA variant"
            ],
            "test_after": "Verify all SHA-1 calls are replaced. Run tests to ensure hash outputs are still handled correctly (they will be longer)."
        }
    },
    {
        "id": "CANOP-CRY-003",
        "pattern": r"""hashlib\.(?:md5|sha1)\s*\(""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "crypto",
        "langs": {".py"},
        "message": "Weak hash function used (md5/sha1)",
        "cwe": "CWE-327",
        "fix": "Use hashlib.sha256() or passlib/bcrypt for passwords",
        "prescription": {
            "task": "Replace weak hashlib hash with SHA-256+",
            "vulnerability": "hashlib.md5() and hashlib.sha1() use broken/deprecated algorithms vulnerable to collision attacks",
            "fix_strategy": "Replace with hashlib.sha256() for integrity or passlib/bcrypt for passwords",
            "fix_patterns": {
                "python": "# Before: hashlib.md5(data.encode()).hexdigest()\n# After:\nhashlib.sha256(data.encode()).hexdigest()"
            },
            "constraints": [
                "Replace hashlib.md5() with hashlib.sha256()",
                "Replace hashlib.sha1() with hashlib.sha256()",
                "If hashing passwords, switch to bcrypt: from passlib.hash import bcrypt",
                "Update any stored hashes or database columns that depend on the old hash length"
            ],
            "test_after": "Grep for hashlib.md5\\|hashlib.sha1 — should return zero results"
        }
    },
    {
        "id": "CANOP-CRY-004",
        "pattern": r"""\bDES\b.*(?:encrypt|cipher|key)|(?:encrypt|cipher|key).*\bDES\b""",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "category": "crypto",
        "langs": {".py", ".js", ".ts", ".java", ".cs"},
        "message": "DES encryption is insecure — key size is too small",
        "cwe": "CWE-327",
        "fix": "Use AES-256-GCM or ChaCha20-Poly1305",
        "prescription": {
            "task": "Replace DES encryption with AES-256-GCM",
            "vulnerability": "DES uses a 56-bit key that can be brute-forced in hours. 3DES is also deprecated since 2023 (NIST SP 800-131A Rev 2)",
            "fix_strategy": "Replace with AES-256-GCM which provides both encryption and authentication",
            "fix_patterns": {
                "python": "from cryptography.fernet import Fernet\nkey = Fernet.generate_key()\nf = Fernet(key)\nencrypted = f.encrypt(plaintext.encode())",
                "javascript": "const crypto = require('crypto');\nconst key = crypto.randomBytes(32);\nconst iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);"
            },
            "constraints": [
                "Replace DES with AES-256-GCM (authenticated encryption)",
                "Generate keys with a CSPRNG (crypto.randomBytes, os.urandom)",
                "Use a unique IV/nonce for every encryption operation",
                "Re-encrypt any data currently encrypted with DES"
            ],
            "test_after": "Grep for DES in encryption contexts — should return zero results"
        }
    },
    {
        "id": "CANOP-CRY-005",
        "pattern": r"""(?i)\b(?:ECB)\b""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "crypto",
        "langs": {".py", ".js", ".ts", ".java", ".go", ".cs"},
        "message": "ECB mode is deterministic and leaks repetition patterns",
        "cwe": "CWE-327",
        "fix": "Use CBC with random IV, or GCM for authenticated encryption",
        "prescription": {
            "task": "Replace ECB mode with GCM or CBC",
            "vulnerability": "ECB (Electronic Codebook) mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns (the famous 'ECB penguin' problem)",
            "fix_strategy": "Replace with AES-GCM (preferred, provides authentication) or AES-CBC with a random IV",
            "fix_patterns": {
                "python": "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nimport os\niv = os.urandom(12)\ncipher = Cipher(algorithms.AES(key), modes.GCM(iv))",
                "java": "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\nbyte[] iv = new byte[12];\nnew SecureRandom().nextBytes(iv);\ncipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));"
            },
            "constraints": [
                "Replace ECB with GCM (preferred) or CBC mode",
                "Always generate a random IV/nonce for each encryption",
                "Never reuse an IV with the same key",
                "GCM also provides authentication (detects tampering) — prefer over CBC"
            ],
            "test_after": "Grep for ECB — should return zero results in encryption code"
        }
    },
    {
        "id": "CANOP-CRY-006",
        "pattern": r"""\brandom\.(random|randint|choice|randrange|sample|shuffle)\b""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "crypto",
        "langs": {".py"},
        "message": "random module is not cryptographically secure",
        "cwe": "CWE-338",
        "fix": "Use secrets module for tokens, passwords, and security-sensitive values",
        "prescription": {
            "task": "Replace random module with secrets for security use",
            "vulnerability": "Python's random module uses a Mersenne Twister PRNG which is predictable — an attacker who observes 624 outputs can predict all future values",
            "fix_strategy": "Use the secrets module for security-sensitive randomness (tokens, passwords, session IDs)",
            "fix_patterns": {
                "python": "import secrets\ntoken = secrets.token_hex(32)  # was: ''.join(random.choice(chars) for _ in range(32))\ncode = secrets.randbelow(1000000)  # was: random.randint(0, 999999)"
            },
            "constraints": [
                "Use secrets.token_hex() or secrets.token_urlsafe() for tokens/API keys",
                "Use secrets.randbelow(n) instead of random.randint()",
                "Use secrets.choice() instead of random.choice() for security-sensitive selections",
                "random module is fine for non-security uses (shuffling UI, games, simulations) — add a comment if keeping"
            ],
            "test_after": "Grep for random\\. in security-related files — all security uses should use secrets module"
        }
    },
    {
        "id": "CANOP-CRY-007",
        "pattern": r"""Math\.random\s*\(""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "crypto",
        "langs": {".js", ".ts", ".jsx", ".tsx"},
        "message": "Math.random() is not cryptographically secure",
        "cwe": "CWE-338",
        "fix": "Use crypto.getRandomValues() or crypto.randomUUID()",
        "prescription": {
            "task": "Replace Math.random() with crypto API for security use",
            "vulnerability": "Math.random() uses a non-cryptographic PRNG (xorshift128+ in V8). Output is predictable and must not be used for tokens, IDs, or security-sensitive values",
            "fix_strategy": "Use the Web Crypto API (crypto.getRandomValues) or crypto.randomUUID() for secure randomness",
            "fix_patterns": {
                "javascript": "// For UUIDs:\nconst id = crypto.randomUUID();\n// For random bytes:\nconst buf = new Uint8Array(32);\ncrypto.getRandomValues(buf);\n// For random int (0 to max):\nconst arr = new Uint32Array(1);\ncrypto.getRandomValues(arr);\nconst num = arr[0] % max;"
            },
            "constraints": [
                "Use crypto.randomUUID() for unique identifiers",
                "Use crypto.getRandomValues() for random bytes/numbers in security contexts",
                "Math.random() is fine for non-security uses (animations, UI) — add a comment if keeping",
                "In Node.js: const { randomBytes, randomUUID } = require('crypto');"
            ],
            "test_after": "Grep for Math.random in auth/token/session files — should use crypto API"
        }
    },
    # ── Deserialization ────────────────────────────────────────────────
    {
        "id": "CANOP-DES-001",
        "pattern": r"""\bpickle\.(?:loads?|Unpickler)\s*\(""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "deserialization",
        "langs": {".py"},
        "message": "Insecure deserialization via pickle (arbitrary code execution)",
        "cwe": "CWE-502",
        "fix": "Use JSON or a safe serialization format",
        "prescription": {
            "task": "Replace pickle with safe serialization",
            "vulnerability": "pickle.load() / pickle.loads() can execute arbitrary Python code during deserialization. An attacker who controls the pickled data gets full RCE",
            "fix_strategy": "Replace with JSON for data exchange, or msgpack/protobuf for binary. If pickle is absolutely required, use hmac signing to verify integrity before unpickling.",
            "fix_patterns": {
                "python": "import json\n# Before: data = pickle.loads(raw)\n# After:\ndata = json.loads(raw)  # safe — only parses JSON types"
            },
            "constraints": [
                "NEVER unpickle data from untrusted sources (network, user upload, external API)",
                "Replace with json.loads() for text data or msgpack for binary",
                "If migrating from pickle, you may need to re-serialize existing data to JSON",
                "If pickle is required (ML models), verify integrity with HMAC before loading",
                "Consider using safetensors for ML model weights instead of pickle"
            ],
            "test_after": "Grep for pickle.load — remaining uses must only load from trusted, integrity-verified sources"
        }
    },
    {
        "id": "CANOP-DES-002",
        "pattern": r"""\byaml\.load\s*\((?![^)]*Loader\s*=)""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "deserialization",
        "langs": {".py"},
        "message": "yaml.load() without SafeLoader allows arbitrary code execution",
        "cwe": "CWE-502",
        "fix": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        "prescription": {
            "task": "Fix unsafe YAML deserialization",
            "vulnerability": "yaml.load() without an explicit safe Loader can instantiate arbitrary Python objects, enabling code execution via crafted YAML (!!python/object payloads)",
            "fix_strategy": "Replace yaml.load() with yaml.safe_load() which only allows basic types",
            "fix_patterns": {
                "python": "import yaml\n# Before: data = yaml.load(raw)\n# After:\ndata = yaml.safe_load(raw)  # only parses basic YAML types"
            },
            "constraints": [
                "Replace yaml.load(x) with yaml.safe_load(x) everywhere",
                "Or use yaml.load(x, Loader=yaml.SafeLoader)",
                "safe_load supports: str, int, float, bool, list, dict, None, datetime",
                "If you need custom types, use yaml.SafeLoader with explicit add_constructor()"
            ],
            "test_after": "Grep for yaml.load( — all calls must use safe_load or explicit Loader=yaml.SafeLoader"
        }
    },
    {
        "id": "CANOP-DES-003",
        "pattern": r"""\bmarshal\.loads?\s*\(""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "deserialization",
        "langs": {".py"},
        "message": "marshal module is not safe for untrusted data",
        "cwe": "CWE-502",
        "fix": "Use JSON for data exchange",
        "prescription": {
            "task": "Replace marshal with JSON serialization",
            "vulnerability": "marshal can deserialize arbitrary code objects. Unlike pickle, it is not even designed for cross-version compatibility, and loading untrusted marshal data can crash or exploit the interpreter",
            "fix_strategy": "Replace with json.loads()/json.dumps() for data exchange",
            "fix_patterns": {
                "python": "import json\n# Before: data = marshal.loads(raw)\n# After:\ndata = json.loads(raw)"
            },
            "constraints": [
                "marshal is only appropriate for .pyc file internals — never for data exchange",
                "Replace with JSON, msgpack, or protobuf",
                "Re-serialize any stored marshal data to the new format"
            ],
            "test_after": "Grep for marshal.load — should not appear in data handling code"
        }
    },
    {
        "id": "CANOP-DES-004",
        "pattern": r"""\bshelve\.open\s*\(""",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "category": "deserialization",
        "langs": {".py"},
        "message": "shelve uses pickle internally — unsafe with untrusted data",
        "cwe": "CWE-502",
        "fix": "Use a database or JSON-based storage",
        "prescription": {
            "task": "Replace shelve with database or JSON storage",
            "vulnerability": "shelve uses pickle internally for serialization, inheriting all of pickle's arbitrary code execution risks",
            "fix_strategy": "Replace with SQLite (for key-value storage), JSON files, or TinyDB",
            "fix_patterns": {
                "python": "import sqlite3, json\nconn = sqlite3.connect('data.db')\nconn.execute('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)')\n# Store: conn.execute('INSERT OR REPLACE INTO kv VALUES (?, ?)', (key, json.dumps(value)))\n# Load: row = conn.execute('SELECT value FROM kv WHERE key = ?', (key,)).fetchone()"
            },
            "constraints": [
                "Replace shelve.open() with SQLite or JSON-based storage",
                "Migrate existing shelve data: open old shelve, iterate, store to new format",
                "If data is user-facing, use a proper database (SQLite, PostgreSQL)"
            ],
            "test_after": "Grep for shelve.open — should return zero results"
        }
    },
    # ── XSS ────────────────────────────────────────────────────────────
    {
        "id": "CANOP-XSS-001",
        "pattern": r"""dangerouslySetInnerHTML""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "xss",
        "langs": {".jsx", ".tsx", ".js", ".ts"},
        "message": "dangerouslySetInnerHTML can lead to XSS if input is unsanitized",
        "cwe": "CWE-79",
        "fix": "Sanitize input with DOMPurify or avoid inner HTML",
        "prescription": {
            "task": "Sanitize or remove dangerouslySetInnerHTML",
            "vulnerability": "dangerouslySetInnerHTML injects raw HTML into the DOM without escaping, allowing XSS if any part of the HTML is user-controlled",
            "fix_strategy": "Sanitize with DOMPurify before injection, or restructure to use React's built-in escaping (JSX text content, textContent)",
            "fix_patterns": {
                "javascript": "import DOMPurify from 'dompurify';\n// Before: <div dangerouslySetInnerHTML={{__html: userContent}} />\n// After:\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />"
            },
            "constraints": [
                "If the content is user-generated, ALWAYS sanitize with DOMPurify.sanitize()",
                "If the content is static/trusted (e.g., from CMS with trusted editors), add a comment documenting why it's safe",
                "Prefer React JSX text content which auto-escapes: <div>{userContent}</div>",
                "Install: npm install dompurify (or isomorphic-dompurify for SSR)"
            ],
            "test_after": "Test with input: <img src=x onerror=alert(1)> — must be stripped or escaped in output"
        }
    },
    {
        "id": "CANOP-XSS-002",
        "pattern": r"""document\.(?:write|writeln)\s*\(""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "xss",
        "langs": {".js", ".ts", ".html"},
        "message": "document.write() can introduce XSS vulnerabilities",
        "cwe": "CWE-79",
        "fix": "Use DOM manipulation APIs (textContent, createElement)",
        "prescription": {
            "task": "Replace document.write() with DOM APIs",
            "vulnerability": "document.write() injects raw HTML and can introduce XSS. It also blocks parsing, hurting performance",
            "fix_strategy": "Use DOM manipulation methods: textContent for text, createElement/appendChild for structure",
            "fix_patterns": {
                "javascript": "// Before: document.write('<p>' + message + '</p>');\n// After:\nconst p = document.createElement('p');\np.textContent = message;  // auto-escapes HTML\ndocument.body.appendChild(p);"
            },
            "constraints": [
                "Replace ALL document.write() calls with DOM APIs",
                "Use textContent (not innerHTML) to auto-escape user content",
                "Use createElement + appendChild for structured content",
                "document.write() called after page load completely replaces the page"
            ],
            "test_after": "Grep for document.write — should return zero results"
        }
    },
    {
        "id": "CANOP-XSS-003",
        "pattern": r"""\.innerHTML\s*=(?!=)""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "xss",
        "langs": {".js", ".ts", ".jsx", ".tsx"},
        "message": "Direct innerHTML assignment may allow XSS",
        "cwe": "CWE-79",
        "fix": "Use textContent or sanitize with DOMPurify",
        "prescription": {
            "task": "Replace innerHTML with textContent or sanitize",
            "vulnerability": "Setting innerHTML with user-controlled content allows XSS — script tags and event handlers in the HTML will execute",
            "fix_strategy": "Use textContent for plain text or DOMPurify.sanitize() if HTML rendering is required",
            "fix_patterns": {
                "javascript": "// For plain text:\nelement.textContent = userInput;  // auto-escapes\n// For HTML (must sanitize):\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userHtml);"
            },
            "constraints": [
                "Default to textContent — it is always safe",
                "Only use innerHTML when you specifically need HTML rendering",
                "If using innerHTML, always sanitize with DOMPurify first",
                "Never assign user input directly to innerHTML"
            ],
            "test_after": "Test with input: <img src=x onerror=alert('xss')> — must be escaped or sanitized"
        }
    },
    {
        "id": "CANOP-XSS-004",
        "pattern": r"""\|\s*safe\b""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "xss",
        "langs": {".html"},
        "message": "Jinja2/Django |safe filter disables autoescaping — XSS risk",
        "cwe": "CWE-79",
        "fix": "Avoid |safe on user-controlled data; sanitize first",
        "prescription": {
            "task": "Remove or guard |safe filter on user content",
            "vulnerability": "|safe tells Jinja2/Django to skip HTML escaping. If the variable contains user input, any HTML/JS in it will render and execute (XSS)",
            "fix_strategy": "Remove |safe and let autoescaping work, or sanitize with bleach/nh3 before marking safe",
            "fix_patterns": {
                "python_django": "import nh3\n# In view:\ncleaned = nh3.clean(user_html, tags={'p', 'br', 'strong', 'em'})\n# In template:\n{{ cleaned|safe }}  {# safe because we sanitized in the view #}"
            },
            "constraints": [
                "Never use |safe on raw user input",
                "If |safe is needed, sanitize FIRST in the view/controller with bleach or nh3",
                "Whitelist only the HTML tags you need (p, br, strong, em, a)",
                "Add a comment explaining why |safe is justified at each usage"
            ],
            "test_after": "Test with input: <script>alert('xss')</script> — must be stripped or escaped"
        }
    },
    # ── Path Traversal ─────────────────────────────────────────────────
    {
        "id": "CANOP-PTH-001",
        "pattern": r"""open\s*\(\s*(?:.*\+|f['\"])""",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "category": "path-traversal",
        "langs": {".py"},
        "message": "Dynamic file path in open() may allow path traversal",
        "cwe": "CWE-22",
        "fix": "Validate and sanitize file paths; use os.path.realpath() to resolve and check",
        "prescription": {
            "task": "Prevent path traversal in dynamic file open()",
            "vulnerability": "User-controlled input in a file path allows an attacker to use ../ sequences to read/write arbitrary files (e.g., ../../etc/passwd)",
            "fix_strategy": "Resolve the full path with os.path.realpath() and verify it starts with the expected base directory",
            "fix_patterns": {
                "python": "import os\nBASE_DIR = '/app/uploads'\nrequested = os.path.realpath(os.path.join(BASE_DIR, user_filename))\nif not requested.startswith(os.path.realpath(BASE_DIR)):\n    raise ValueError('Path traversal detected')\nwith open(requested) as f:\n    data = f.read()"
            },
            "constraints": [
                "Always resolve with os.path.realpath() to eliminate ../ and symlinks",
                "Check that the resolved path starts with your allowed base directory",
                "Reject filenames containing ../ or absolute paths",
                "Strip or reject null bytes in filenames",
                "Use pathlib.Path.resolve() as an alternative"
            ],
            "test_after": "Attempt input: ../../../etc/passwd — must be rejected, not served"
        }
    },
    {
        "id": "CANOP-PTH-002",
        "pattern": r"""(?:send_file|send_from_directory)\s*\(\s*(?:.*\+|f['\"])""",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "category": "path-traversal",
        "langs": {".py"},
        "message": "Dynamic path in Flask file-serving function — path traversal risk",
        "cwe": "CWE-22",
        "fix": "Use os.path.realpath() and verify the path is within the allowed directory",
        "prescription": {
            "task": "Secure Flask file-serving against path traversal",
            "vulnerability": "Dynamic path in send_file/send_from_directory allows file access outside the intended directory via ../ sequences",
            "fix_strategy": "Use send_from_directory with a fixed base directory and validate the filename. Use secure_filename() from werkzeug.",
            "fix_patterns": {
                "python": "from flask import send_from_directory\nfrom werkzeug.utils import secure_filename\nimport os\n\n@app.route('/download/<filename>')\ndef download(filename):\n    safe_name = secure_filename(filename)  # strips ../ and special chars\n    return send_from_directory('/app/uploads', safe_name)"
            },
            "constraints": [
                "Use werkzeug.utils.secure_filename() on user-provided filenames",
                "Use send_from_directory() with a hardcoded base directory",
                "Never concatenate user input into file paths with f-strings or +",
                "Verify the resolved path is within the allowed directory"
            ],
            "test_after": "Attempt: /download/../../etc/passwd — must return 404, not file contents"
        }
    },
    # ── Insecure Configuration ─────────────────────────────────────────
    {
        "id": "CANOP-CFG-001",
        "pattern": r"""(?i)^\s*(?:app\.)?debug\s*=\s*True""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "configuration",
        "langs": {".py"},
        "message": "Debug mode enabled — must be disabled in production",
        "cwe": "CWE-489",
        "fix": "Set DEBUG=False and control via environment variable",
        "prescription": {
            "task": "Disable debug mode for production",
            "vulnerability": "Debug mode exposes stack traces, internal variables, and often an interactive debugger (Werkzeug) to end users, leaking sensitive internal details",
            "fix_strategy": "Control debug mode via environment variable, defaulting to False",
            "fix_patterns": {
                "python_flask": "app.debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'",
                "python_django": "# settings.py\nDEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'",
                "python_fastapi": "# Use a settings class\nclass Settings:\n    debug: bool = os.environ.get('DEBUG', 'false').lower() == 'true'"
            },
            "constraints": [
                "Set DEBUG=False in production (environment variable or settings)",
                "Never hardcode DEBUG=True in committed code",
                "In Django: also set ALLOWED_HOSTS when DEBUG=False",
                "Use environment variables: DEBUG=true only in local .env"
            ],
            "test_after": "Verify DEBUG is False in production: check deployed environment variables and response headers"
        }
    },
    {
        "id": "CANOP-CFG-002",
        "pattern": r"""(?i)\bverify\s*=\s*False\b""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "configuration",
        "langs": {".py"},
        "message": "SSL/TLS certificate verification disabled — vulnerable to MITM attacks",
        "cwe": "CWE-295",
        "fix": "Always verify SSL certificates in production",
        "prescription": {
            "task": "Re-enable SSL certificate verification",
            "vulnerability": "verify=False disables TLS certificate validation, allowing man-in-the-middle attacks. An attacker on the network can intercept and modify traffic",
            "fix_strategy": "Remove verify=False (default is True). If you need a custom CA, point to a CA bundle file.",
            "fix_patterns": {
                "python": "# Before: requests.get(url, verify=False)\n# After:\nrequests.get(url)  # verify=True is the default\n# If using a private CA:\nrequests.get(url, verify='/path/to/ca-bundle.crt')"
            },
            "constraints": [
                "Remove verify=False from ALL requests/urllib3 calls",
                "If dealing with self-signed certs in dev: use verify=False ONLY in local dev, controlled by env var",
                "For private CAs: pass the CA bundle path to verify= instead of disabling",
                "Never disable verification in production code"
            ],
            "test_after": "Grep for verify=False — should only appear in explicitly dev-only code paths with env var guards"
        }
    },
    {
        "id": "CANOP-CFG-003",
        "pattern": r"""(?i)allow_origins\s*=\s*\[\s*['\"\s]*\*['\"\s]*\]""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "configuration",
        "langs": {".py"},
        "message": "CORS wildcard '*' allows requests from any origin",
        "cwe": "CWE-942",
        "fix": "Restrict allow_origins to your frontend domain(s)",
        "prescription": {
            "task": "Restrict CORS to specific origins",
            "vulnerability": "CORS wildcard (*) allows any website to make authenticated API requests to your backend, enabling data theft via cross-origin requests",
            "fix_strategy": "Replace '*' with a list of your actual frontend domains",
            "fix_patterns": {
                "python_fastapi": "from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=[\n        'https://yourdomain.com',\n        'http://localhost:3000',  # dev only\n    ],\n    allow_credentials=True,\n    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n    allow_headers=['Authorization', 'Content-Type'],\n)"
            },
            "constraints": [
                "List only YOUR frontend domains in allow_origins",
                "Use environment variable for origin list so dev/staging/prod differ",
                "If allow_credentials=True, CORS does not accept '*' anyway — you must specify origins",
                "Include localhost origins only in development environments"
            ],
            "test_after": "Make a cross-origin request from an unauthorized domain — should be blocked by CORS"
        }
    },
    {
        "id": "CANOP-CFG-004",
        "pattern": r"""(?i)(?:SECURE_SSL_REDIRECT|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "configuration",
        "langs": {".py"},
        "message": "Django security setting disabled — insecure in production",
        "cwe": "CWE-614",
        "fix": "Set to True in production settings",
        "prescription": {
            "task": "Enable Django security settings for production",
            "vulnerability": "Disabled security settings expose the application to session hijacking (cookies sent over HTTP), CSRF attacks, and lack of HTTPS enforcement",
            "fix_strategy": "Set all security flags to True in production settings. Use separate settings files or environment variables for dev vs prod.",
            "fix_patterns": {
                "python": "# settings/production.py\nSECURE_SSL_REDIRECT = True\nSESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True"
            },
            "constraints": [
                "Set SECURE_SSL_REDIRECT=True to force HTTPS",
                "Set SESSION_COOKIE_SECURE=True so session cookies only sent over HTTPS",
                "Set CSRF_COOKIE_SECURE=True so CSRF tokens only sent over HTTPS",
                "Also consider SECURE_HSTS_SECONDS for HSTS header",
                "These should only be False in local dev (use django-environ or split settings)"
            ],
            "test_after": "Run: python manage.py check --deploy — should pass all security checks"
        }
    },
    # ── JWT / Auth ─────────────────────────────────────────────────────
    {
        "id": "CANOP-JWT-001",
        "pattern": r"""(?i)algorithms?\s*=\s*\[?\s*['\"]none['\"]""",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "auth",
        "langs": {".py", ".js", ".ts"},
        "message": "JWT 'none' algorithm allows unsigned token forgery",
        "cwe": "CWE-345",
        "fix": "Enforce specific algorithms (e.g. HS256, RS256)",
        "prescription": {
            "task": "Remove JWT 'none' algorithm and enforce specific algorithm",
            "vulnerability": "'none' algorithm means the JWT has no signature. An attacker can forge any token (change user_id, role=admin) and the server will accept it",
            "fix_strategy": "Explicitly set the allowed algorithm(s) to HS256 or RS256 and reject 'none'",
            "fix_patterns": {
                "python": "import jwt\n# Encoding:\ntoken = jwt.encode(payload, SECRET_KEY, algorithm='HS256')\n# Decoding — ALWAYS specify algorithms:\ndata = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])",
                "javascript": "const jwt = require('jsonwebtoken');\n// Always specify algorithm:\njwt.verify(token, secret, { algorithms: ['HS256'] });"
            },
            "constraints": [
                "NEVER include 'none' in the algorithms list",
                "Always specify algorithms= explicitly when decoding/verifying",
                "Use HS256 (symmetric) for single-service apps or RS256 (asymmetric) for microservices",
                "Pin to exactly ONE algorithm — never allow fallback to weaker ones"
            ],
            "test_after": "Craft a JWT with algorithm='none' and empty signature — server must reject it"
        }
    },
    {
        "id": "CANOP-JWT-002",
        "pattern": r"""(?i)(?:secret|jwt)[_\-]?(?:key|secret)\s*=\s*['\"](?:secret|changeme|password|your[_\-]?secret|test|example|demo|default|key)['\"]""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "auth",
        "langs": {".py", ".js", ".ts", ".env"},
        "message": "Weak or default secret key detected",
        "cwe": "CWE-798",
        "fix": "Generate a strong random key: openssl rand -hex 32",
        "skip_in_strings": False,
        "prescription": {
            "task": "Replace weak JWT/app secret with a strong random key",
            "vulnerability": "Default or weak secret keys (secret, changeme, password) are trivially guessable. An attacker can forge JWT tokens or decrypt session data",
            "fix_strategy": "Generate a 256-bit random secret and store it as an environment variable",
            "fix_patterns": {
                "generate": "# Generate a strong secret:\n# Terminal: openssl rand -hex 32\n# Python: python -c \"import secrets; print(secrets.token_hex(32))\"",
                "python": "import os\nSECRET_KEY = os.environ['SECRET_KEY']  # must be set in .env or deployment config",
                "javascript": "const SECRET_KEY = process.env.SECRET_KEY;\nif (!SECRET_KEY || SECRET_KEY.length < 32) throw new Error('SECRET_KEY must be set');"
            },
            "constraints": [
                "Generate with: openssl rand -hex 32 (produces 64 hex chars = 256 bits)",
                "Store in environment variable, never in source code",
                "Minimum 256 bits (32 bytes / 64 hex chars) for HS256",
                "Use different secrets per environment (dev, staging, prod)",
                "After changing the secret, all existing JWTs will be invalidated (users must re-login)"
            ],
            "test_after": "Verify SECRET_KEY is read from env var. Run: grep -ri 'secret.*=.*changeme\\|secret.*=.*password' — should return zero results"
        }
    },
    {
        "id": "CANOP-JWT-003",
        "pattern": r"""(?i)\bassert\b.*(?:is_admin|is_authenticated|has_permission|is_authorized|role\s*==)""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "auth",
        "langs": {".py"},
        "message": "assert used for authorization check — stripped in optimized mode (-O)",
        "cwe": "CWE-617",
        "fix": "Use if/raise instead of assert for security checks",
        "prescription": {
            "task": "Replace assert with if/raise for auth checks",
            "vulnerability": "Python's assert statements are completely removed when running with -O (optimize) flag. Authorization checks using assert will silently pass, granting access to everyone",
            "fix_strategy": "Replace assert with explicit if check and raise an appropriate exception",
            "fix_patterns": {
                "python": "# Before: assert user.is_admin, 'Unauthorized'\n# After:\nif not user.is_admin:\n    raise PermissionError('Admin access required')  # or return 403 response\n\n# In Flask/FastAPI:\nfrom fastapi import HTTPException\nif not current_user.is_admin:\n    raise HTTPException(status_code=403, detail='Forbidden')"
            },
            "constraints": [
                "Replace ALL assert statements used for authorization/authentication",
                "Use if/raise with appropriate exception type (PermissionError, HTTPException 403)",
                "assert is for development-time invariants, NEVER for runtime security checks",
                "Search for: assert.*is_admin, assert.*is_authenticated, assert.*role"
            ],
            "test_after": "Run the app with python -O and verify auth checks still work. All protected endpoints must still reject unauthorized users."
        }
    },
    # ── SSRF ───────────────────────────────────────────────────────────
    {
        "id": "CANOP-SSRF-001",
        "pattern": r"""requests\.(?:get|post|put|delete|patch|head)\s*\(\s*(?:f['\"]|.*\+|\w*url\w*|.*\.format)""",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "category": "ssrf",
        "langs": {".py"},
        "message": "Dynamic URL in HTTP request may enable SSRF",
        "cwe": "CWE-918",
        "fix": "Validate URLs against an allowlist before making requests",
        "prescription": {
            "task": "Prevent SSRF in dynamic HTTP requests",
            "vulnerability": "User-controlled URL in an HTTP request allows an attacker to make the server request internal resources (localhost, cloud metadata at 169.254.169.254, internal services)",
            "fix_strategy": "Validate the URL against an allowlist of permitted domains/IPs. Block private/internal IPs.",
            "fix_patterns": {
                "python": "from urllib.parse import urlparse\nimport ipaddress\n\nALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n\ndef safe_request(url):\n    parsed = urlparse(url)\n    if parsed.hostname not in ALLOWED_HOSTS:\n        raise ValueError(f'Host not allowed: {parsed.hostname}')\n    # Also block private IPs\n    ip = ipaddress.ip_address(parsed.hostname)\n    if ip.is_private or ip.is_loopback:\n        raise ValueError('Internal addresses not allowed')\n    return requests.get(url)"
            },
            "constraints": [
                "Validate URL hostname against an allowlist of permitted domains",
                "Block private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8",
                "Block cloud metadata: 169.254.169.254",
                "Resolve hostname and check the IP AFTER DNS resolution (to prevent DNS rebinding)",
                "Disable HTTP redirects or validate redirect targets too: allow_redirects=False"
            ],
            "test_after": "Attempt URLs: http://127.0.0.1, http://169.254.169.254/latest/meta-data/, http://internal-service — all must be rejected"
        }
    },
    {
        "id": "CANOP-SSRF-002",
        "pattern": r"""(?:urllib|urlopen|httplib|http\.client)\.\w+\s*\(\s*(?:f['\"]|.*\+)""",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "category": "ssrf",
        "langs": {".py"},
        "message": "Dynamic URL in HTTP request may enable SSRF",
        "cwe": "CWE-918",
        "fix": "Validate URLs against an allowlist before making requests",
        "prescription": {
            "task": "Prevent SSRF in urllib/http.client requests",
            "vulnerability": "User-controlled URL in urllib/http.client allows server-side request forgery to internal services and cloud metadata endpoints",
            "fix_strategy": "Validate URL against domain allowlist and block private/internal IPs before making the request",
            "fix_patterns": {
                "python": "from urllib.parse import urlparse\n\ndef validate_url(url):\n    parsed = urlparse(url)\n    if parsed.scheme not in ('http', 'https'):\n        raise ValueError('Only HTTP(S) allowed')\n    if parsed.hostname in ('localhost', '127.0.0.1', '169.254.169.254'):\n        raise ValueError('Internal addresses blocked')\n    return url\n\nvalidated = validate_url(user_url)\nurllib.request.urlopen(validated)"
            },
            "constraints": [
                "Validate URL scheme (only http/https), hostname, and resolved IP",
                "Block localhost, 127.0.0.1, 0.0.0.0, 169.254.169.254, and private ranges",
                "Consider using a dedicated SSRF-prevention library",
                "Apply the same validation to any URL from user input, database, or external API"
            ],
            "test_after": "Attempt: urlopen('http://169.254.169.254/latest/meta-data/') — must be rejected"
        }
    },
    # ── Logging / Information Exposure ─────────────────────────────────
    {
        "id": "CANOP-LOG-001",
        "pattern": r"""(?i)(?:print|console\.log|logger?\.\w+)\s*\(.*\b(?:password|passwd|secret|api_key|token|credit_card|ssn|private_key)\s*(?:\)|,|\+|})""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "information-exposure",
        "langs": {".py", ".js", ".ts", ".java"},
        "message": "Sensitive variable may be written to logs",
        "cwe": "CWE-532",
        "fix": "Never log credentials, tokens, or PII; redact sensitive fields",
        "prescription": {
            "task": "Remove sensitive data from log output",
            "vulnerability": "Logging credentials, tokens, or PII means they appear in log files, log aggregation services, and error tracking tools — accessible to ops teams, third-party services, and potentially attackers",
            "fix_strategy": "Remove the sensitive variable from the log statement or redact it",
            "fix_patterns": {
                "python": "# Before: logger.info(f'Login attempt for {email} with token {token}')\n# After:\nlogger.info(f'Login attempt for {email}')  # never log tokens\n# Or redact:\nlogger.info(f'Token: {token[:4]}...{token[-4:]}')",
                "javascript": "// Before: console.log('API key:', apiKey);\n// After:\nconsole.log('API key: [REDACTED]');"
            },
            "constraints": [
                "Never log: passwords, tokens, API keys, credit card numbers, SSNs, private keys",
                "If debugging requires seeing a value, log only first/last 4 chars: token[:4]...",
                "Use structured logging with a redaction filter for sensitive field names",
                "Review log aggregation service access controls"
            ],
            "test_after": "Search log output for password, token, api_key — should never contain actual values"
        }
    },
    {
        "id": "CANOP-LOG-002",
        "pattern": r"""(?i)(?:print|console\.log|logger?\.\w+)\s*\(.*\bf['\"].*\{(?:password|passwd|secret|api_key|token|private_key)""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "information-exposure",
        "langs": {".py", ".js", ".ts"},
        "message": "Sensitive variable interpolated in log statement",
        "cwe": "CWE-532",
        "fix": "Never log credentials or tokens; redact sensitive values",
        "prescription": {
            "task": "Remove interpolated secrets from log statements",
            "vulnerability": "Sensitive variables directly interpolated into f-string log messages. The full secret value will appear in log files and monitoring systems",
            "fix_strategy": "Remove the sensitive variable from the f-string or replace with a redacted placeholder",
            "fix_patterns": {
                "python": "# Before: logger.error(f'Auth failed with password={password}')\n# After:\nlogger.error('Auth failed for user', extra={'user_id': user.id})  # structured, no secrets"
            },
            "constraints": [
                "Remove ALL secret/password/token variables from f-string log messages",
                "Use structured logging (extra={}) with only non-sensitive identifiers",
                "Consider a logging filter that auto-redacts sensitive patterns"
            ],
            "test_after": "Grep for log.*password|log.*token|log.*secret in string interpolation — should return zero matches"
        }
    },
    # ── Regex DoS ──────────────────────────────────────────────────────
    {
        "id": "CANOP-DOS-001",
        "pattern": r"""re\.(?:match|search|findall|sub|compile)\s*\([^)]*(?:\.\*\.\*|\.\+\.\+|\(\.[*+]\)\+|\(\.[*+]\)\*)""",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "category": "dos",
        "langs": {".py"},
        "message": "Potentially catastrophic regex — ReDoS risk",
        "cwe": "CWE-1333",
        "fix": "Simplify the regex, add anchors, or use a timeout",
        "prescription": {
            "task": "Fix catastrophic backtracking in regex",
            "vulnerability": "Nested quantifiers (e.g., (.*)*) cause exponential backtracking on certain inputs, allowing an attacker to cause denial of service with a crafted string",
            "fix_strategy": "Simplify the regex by removing nested quantifiers, use atomic groups or possessive quantifiers, or add a timeout",
            "fix_patterns": {
                "python": "import re\n# Add timeout (Python 3.11+):\nre.search(pattern, text, timeout=1.0)\n# Or use re2 library for guaranteed linear-time matching:\nimport re2\nre2.search(pattern, text)"
            },
            "constraints": [
                "Avoid patterns like (a+)+ or (a*)*b or (a|b*)* — these cause exponential backtracking",
                "Add ^ and $ anchors to constrain matching",
                "Use re.search(pattern, text, timeout=X) in Python 3.11+",
                "Consider the re2 library (google-re2) for guaranteed O(n) matching",
                "Test regex with ReDoS checker tools before deploying"
            ],
            "test_after": "Test with a long input of repeating characters (e.g., 'a' * 10000) — should complete in <1 second"
        }
    },
    # ── Timing Attacks ─────────────────────────────────────────────────
    {
        "id": "CANOP-TIM-001",
        "pattern": r"""(?i)(?:password|token|secret|key|hash|signature|digest)\s*==\s*""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "timing-attack",
        "langs": {".py"},
        "message": "Exact comparison of secret value is vulnerable to timing attacks",
        "cwe": "CWE-208",
        "fix": "Use hmac.compare_digest() for constant-time comparison",
        "prescription": {
            "task": "Use constant-time comparison for secret values",
            "vulnerability": "The == operator short-circuits on first differing byte, leaking information about the expected value through response timing. An attacker can brute-force the secret one byte at a time",
            "fix_strategy": "Replace == with hmac.compare_digest() which always compares all bytes in constant time",
            "fix_patterns": {
                "python": "import hmac\n# Before: if token == expected_token:\n# After:\nif hmac.compare_digest(token.encode(), expected_token.encode()):"
            },
            "constraints": [
                "Use hmac.compare_digest() for ALL comparisons of: tokens, passwords, signatures, API keys, hashes",
                "Both arguments must be bytes or both strings (encode if needed)",
                "This applies to webhook signature verification, HMAC checks, and token validation",
                "The == operator is fine for non-secret values (user IDs, emails)"
            ],
            "test_after": "Grep for (token|password|secret|hash)==  — all should use hmac.compare_digest instead"
        }
    },
    {
        "id": "CANOP-TIM-002",
        "pattern": r"""(?i)(?:password|token|secret|key|hash|signature|digest)\s*===?\s*""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "timing-attack",
        "langs": {".js", ".ts"},
        "message": "Exact comparison of secret value is vulnerable to timing attacks",
        "cwe": "CWE-208",
        "fix": "Use crypto.timingSafeEqual() for constant-time comparison",
        "prescription": {
            "task": "Use constant-time comparison for secret values",
            "vulnerability": "JavaScript === operator short-circuits on first differing character, leaking timing information about the expected value",
            "fix_strategy": "Replace === with crypto.timingSafeEqual() which compares all bytes in constant time",
            "fix_patterns": {
                "javascript": "const crypto = require('crypto');\n// Before: if (token === expectedToken)\n// After:\nconst a = Buffer.from(token);\nconst b = Buffer.from(expectedToken);\nif (a.length === b.length && crypto.timingSafeEqual(a, b)) {"
            },
            "constraints": [
                "Use crypto.timingSafeEqual() for tokens, signatures, API keys, hashes",
                "Both buffers MUST be the same length (check length first, or pad)",
                "If lengths differ, still do a comparison against a dummy to avoid length oracle: timingSafeEqual(a, Buffer.alloc(a.length))",
                "This is critical for webhook signature verification (Stripe, GitHub webhooks)"
            ],
            "test_after": "Grep for (token|secret|signature)=== — all should use crypto.timingSafeEqual"
        }
    },
    # ── Miscellaneous ──────────────────────────────────────────────────
    {
        "id": "CANOP-MIS-001",
        "pattern": r"""target\s*=\s*['\"]_blank['\"](?![^>]*rel\s*=\s*['\"][^'\"]*noopener)""",
        "severity": "LOW",
        "confidence": "HIGH",
        "category": "miscellaneous",
        "langs": {".html", ".jsx", ".tsx"},
        "message": "Link with target=\"_blank\" without rel=\"noopener\" enables tabnabbing",
        "cwe": "CWE-1022",
        "fix": "Add rel=\"noopener noreferrer\" to external links",
        "skip_in_strings": False,
        "prescription": {
            "task": "Add rel='noopener noreferrer' to target='_blank' links",
            "vulnerability": "Without rel='noopener', the opened page can access window.opener and redirect your page to a phishing site (reverse tabnabbing)",
            "fix_strategy": "Add rel='noopener noreferrer' to every link with target='_blank'",
            "fix_patterns": {
                "html": "<a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\">Link</a>",
                "jsx": "<a href={url} target=\"_blank\" rel=\"noopener noreferrer\">{text}</a>"
            },
            "constraints": [
                "Add rel='noopener noreferrer' to ALL links with target='_blank'",
                "noopener prevents window.opener access",
                "noreferrer also hides the referring URL from the target site",
                "Modern browsers (2023+) add noopener by default, but add it explicitly for compatibility"
            ],
            "test_after": "Search for target=\"_blank\" — every instance must have rel=\"noopener\" or rel=\"noopener noreferrer\""
        }
    },
    {
        "id": "CANOP-MIS-002",
        "pattern": r"""(?i)(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*(?:security|auth|password|token|hack|workaround|temporary|unsafe)""",
        "severity": "INFO",
        "confidence": "LOW",
        "category": "code-quality",
        "langs": None,
        "message": "Security-related TODO/FIXME comment — unfinished security work",
        "cwe": "CWE-546",
        "fix": "Resolve the TODO before deploying to production",
        "skip_in_strings": True,
        "prescription": {
            "task": "Resolve security-related TODO/FIXME",
            "vulnerability": "An unfinished TODO or FIXME related to security means there is a known security gap that has not been addressed. These are easy targets for attackers reviewing open-source code",
            "fix_strategy": "Implement the security fix described in the TODO comment, then remove the comment",
            "fix_patterns": {
                "any": "# 1. Read the TODO/FIXME comment to understand what security work is pending\n# 2. Implement the fix described\n# 3. Remove the TODO comment\n# 4. Add tests to verify the security behavior"
            },
            "constraints": [
                "Address the security concern described in the comment",
                "Remove the TODO/FIXME after implementing the fix",
                "If the fix cannot be done immediately, create a tracked issue/ticket",
                "Never deploy code with unresolved security TODOs to production"
            ],
            "test_after": "Grep for TODO.*security\\|FIXME.*auth\\|HACK.*password — should return zero results in production code"
        }
    },

    # ── NEW: Command Injection ─────────────────────────────────────────
    {
        "id": "CANOP-CMD-001",
        "pattern": r"""subprocess\.(?:run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "command-injection",
        "langs": {".py"},
        "message": "subprocess with shell=True enables command injection",
        "cwe": "CWE-78",
        "fix": "Use shell=False (default) and pass a list of args instead of a string",
        "skip_in_strings": True,
        "prescription": {
            "task": "Remove shell=True from subprocess call",
            "vulnerability": "When shell=True, the command string is interpreted by the system shell (/bin/sh). If any user-controlled data reaches the command, an attacker can inject arbitrary commands using shell metacharacters (;, |, &&, $(), etc.)",
            "fix_strategy": "Pass the command as a list of strings with shell=False (the default). Use shlex.split() to convert a command string to a list if needed.",
            "fix_patterns": {
                "python": "# Before: subprocess.run('git log --pretty=%ct', shell=True)\n# After:\nimport shlex\nsubprocess.run(['git', 'log', '--pretty=%ct'], shell=False)\n# Or: subprocess.run(shlex.split('git log --pretty=%ct'))"
            },
            "constraints": [
                "Never concatenate user input into a shell command string",
                "Use shell=False (the default) and pass a list of arguments",
                "If you must use shell features (pipes, redirects), use subprocess.PIPE instead",
                "Validate/sanitize any external input that reaches command arguments"
            ],
            "test_after": "Grep for 'shell=True' — should return zero results"
        }
    },
    {
        "id": "CANOP-CMD-002",
        "pattern": r"""\bos\.system\s*\(""",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "command-injection",
        "langs": {".py"},
        "message": "os.system() runs commands via shell and is vulnerable to injection",
        "cwe": "CWE-78",
        "fix": "Use subprocess.run() with shell=False instead of os.system()",
        "skip_in_strings": True,
        "prescription": {
            "task": "Replace os.system() with subprocess.run()",
            "vulnerability": "os.system() always invokes the system shell, making it trivially vulnerable to command injection if any part of the command includes user input",
            "fix_strategy": "Replace os.system(cmd) with subprocess.run(cmd_list, check=True) where cmd_list is a list of arguments",
            "fix_patterns": {
                "python": "# Before: os.system(f'rm -rf {path}')\n# After:\nimport subprocess\nsubprocess.run(['rm', '-rf', path], check=True)"
            },
            "constraints": [
                "Never pass user-controlled strings to os.system()",
                "Use subprocess.run() with a list of args for all external commands",
                "Set check=True to raise on non-zero exit codes"
            ],
            "test_after": "Grep for 'os.system(' — should return zero results"
        }
    },

    # ── NEW: CSRF ──────────────────────────────────────────────────────
    {
        "id": "CANOP-CSRF-001",
        "pattern": r"""@csrf_exempt""",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "csrf",
        "langs": {".py"},
        "message": "CSRF protection disabled — endpoint is vulnerable to cross-site request forgery",
        "cwe": "CWE-352",
        "fix": "Remove @csrf_exempt or add alternative CSRF validation (token header, SameSite cookie)",
        "skip_in_strings": True,
        "prescription": {
            "task": "Re-enable CSRF protection on this view",
            "vulnerability": "@csrf_exempt disables Django's built-in CSRF middleware for this endpoint. An attacker can craft a malicious page that submits a form to this endpoint on behalf of an authenticated user",
            "fix_strategy": "Remove @csrf_exempt. If the endpoint is an API, use token-based auth (JWT, API keys) that is naturally CSRF-safe, or enforce a custom CSRF header",
            "fix_patterns": {
                "python": "# Before:\n# @csrf_exempt\n# def my_view(request): ...\n\n# After (option 1 — re-enable CSRF):\ndef my_view(request):\n    ...  # Django CSRF middleware protects automatically\n\n# After (option 2 — API token auth):\nfrom rest_framework.decorators import api_view, authentication_classes\nfrom rest_framework.authentication import TokenAuthentication\n@api_view(['POST'])\n@authentication_classes([TokenAuthentication])\ndef my_view(request):\n    ..."
            },
            "constraints": [
                "Never disable CSRF on endpoints that modify state (POST, PUT, DELETE)",
                "If the endpoint is a webhook, validate via signature/HMAC instead",
                "If using SPA + API, use SameSite=Strict cookies or token auth",
                "Ensure all forms include {% csrf_token %} template tag"
            ],
            "test_after": "Grep for '@csrf_exempt' — should return zero results in production views"
        }
    },

    # ── NEW: XXE ───────────────────────────────────────────────────────
    {
        "id": "CANOP-XXE-001",
        "pattern": r"""(?:from\s+xml\.(?:etree|dom|sax|parsers)\s+import|import\s+xml\.(?:etree|dom|sax|parsers))""",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "xxe",
        "langs": {".py"},
        "message": "Stdlib XML parser may be vulnerable to XXE attacks — use defusedxml",
        "cwe": "CWE-611",
        "fix": "Use defusedxml instead of stdlib xml.etree/xml.dom/xml.sax",
        "skip_in_strings": True,
        "prescription": {
            "task": "Replace stdlib XML parsing with defusedxml",
            "vulnerability": "Python's built-in XML parsers (xml.etree.ElementTree, xml.dom, xml.sax) do not disable external entity processing by default. An attacker can craft XML input that reads local files (XXE), performs SSRF, or causes denial of service (billion laughs attack)",
            "fix_strategy": "Install and use the defusedxml library, which wraps stdlib XML parsers with safe defaults",
            "fix_patterns": {
                "python": "# Before:\nimport xml.etree.ElementTree as ET\ntree = ET.parse(user_file)\n\n# After:\nimport defusedxml.ElementTree as ET\ntree = ET.parse(user_file)  # entities disabled, DTDs blocked"
            },
            "constraints": [
                "Install defusedxml: pip install defusedxml",
                "Replace all 'import xml.etree.ElementTree' with 'import defusedxml.ElementTree'",
                "Replace xml.dom.minidom with defusedxml.minidom",
                "Replace xml.sax with defusedxml.sax",
                "If you need lxml, use lxml with resolve_entities=False"
            ],
            "test_after": "Attempt parsing: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root> — must raise an error"
        }
    },

    # ── NEW: YAML ──────────────────────────────────────────────────────
    {
        "id": "CANOP-YAML-001",
        "pattern": r"""yaml\.load\s*\([^)]*\)(?!\s*#\s*nosec)""",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "category": "deserialization",
        "langs": {".py"},
        "message": "yaml.load() without SafeLoader allows arbitrary code execution",
        "cwe": "CWE-502",
        "fix": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        "skip_in_strings": True,
        "prescription": {
            "task": "Use yaml.safe_load() instead of yaml.load()",
            "vulnerability": "PyYAML's yaml.load() can instantiate arbitrary Python objects via YAML tags like !!python/object. An attacker who controls the YAML input can execute arbitrary code",
            "fix_strategy": "Replace yaml.load() with yaml.safe_load() which only allows basic YAML types (str, int, float, list, dict, bool, None)",
            "fix_patterns": {
                "python": "# Before: data = yaml.load(file_contents)\n# After:\ndata = yaml.safe_load(file_contents)\n# Or:\ndata = yaml.load(file_contents, Loader=yaml.SafeLoader)"
            },
            "constraints": [
                "Replace all yaml.load() calls with yaml.safe_load()",
                "If you need custom types, use yaml.load(data, Loader=yaml.SafeLoader) and register constructors",
                "For dumping, use yaml.safe_dump() to prevent accidental object tags in output",
                "pin PyYAML >= 6.0 where load() without Loader raises a warning"
            ],
            "test_after": "Attempt loading: !!python/object/apply:os.system ['echo pwned'] — must raise an error"
        }
    },

    # ── NEW: Insecure Cookie ───────────────────────────────────────────
    {
        "id": "CANOP-COOKIE-001",
        "pattern": r"""\.set_cookie\s*\([^)]{5,}\)""",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "category": "misconfiguration",
        "langs": {".py", ".js", ".ts"},
        "message": "Cookie set without explicit secure/httponly flags — review for missing protections",
        "cwe": "CWE-614",
        "fix": "Set secure=True, httponly=True, and samesite='Lax' on all sensitive cookies",
        "skip_in_strings": True,
        "prescription": {
            "task": "Add secure flags to cookie",
            "vulnerability": "Cookies set without secure=True can be transmitted over HTTP (intercepted via MITM). Without httponly=True, JavaScript can access the cookie (XSS cookie theft). Without samesite, the cookie is sent with cross-site requests (CSRF)",
            "fix_strategy": "Add secure=True, httponly=True, and samesite='Lax' (or 'Strict') to all sensitive cookies",
            "fix_patterns": {
                "python": "# Before: response.set_cookie('session', value=token)\n# After:\nresponse.set_cookie(\n    'session',\n    value=token,\n    httponly=True,\n    secure=True,\n    samesite='Lax',\n    max_age=3600\n)",
                "javascript": "// Before: res.cookie('session', token)\n// After:\nres.cookie('session', token, {\n    httpOnly: true,\n    secure: true,\n    sameSite: 'lax',\n    maxAge: 3600000\n})"
            },
            "constraints": [
                "Always set httponly=True for session/auth cookies",
                "Always set secure=True in production (HTTPS)",
                "Set samesite='Lax' or 'Strict' to prevent CSRF",
                "Set a reasonable max_age/expires",
                "For development, you may use secure=False but never in production"
            ],
            "test_after": "Check Set-Cookie response header — must contain Secure; HttpOnly; SameSite=Lax"
        }
    },

    # ── NEW: Open Redirect ─────────────────────────────────────────────
    {
        "id": "CANOP-REDIR-001",
        "pattern": r"""redirect\s*\(\s*(?:request\.(?:GET|POST|args|form|query_params|query_string|params)(?:\[|\.get\()|.*\brequest\b.*\bnext\b)""",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "category": "open-redirect",
        "langs": {".py"},
        "message": "Redirect to user-controlled URL — potential open redirect vulnerability",
        "cwe": "CWE-601",
        "fix": "Validate the redirect URL against an allowlist of trusted domains or use a relative-only redirect",
        "skip_in_strings": True,
        "prescription": {
            "task": "Validate redirect destination to prevent open redirect",
            "vulnerability": "Redirecting to a URL from user input (e.g. request.GET['next']) allows an attacker to craft a link that redirects authenticated users to a phishing site: https://yourapp.com/login?next=https://evil.com",
            "fix_strategy": "Validate the redirect URL: only allow relative paths, or check the host against an allowlist",
            "fix_patterns": {
                "python": "# Django:\nfrom django.utils.http import url_has_allowed_host_and_scheme\nnext_url = request.GET.get('next', '/')\nif not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):\n    next_url = '/'\nreturn redirect(next_url)\n\n# Flask:\nfrom urllib.parse import urlparse\nnext_url = request.args.get('next', '/')\nif urlparse(next_url).netloc:  # has a domain = external\n    next_url = '/'\nreturn redirect(next_url)"
            },
            "constraints": [
                "Never pass user input directly to redirect()",
                "Reject URLs with a netloc/host component (external URLs)",
                "Only allow relative paths or paths to your own domain",
                "Django: use url_has_allowed_host_and_scheme()",
                "Use a default fallback like '/' if validation fails"
            ],
            "test_after": "Test with ?next=https://evil.com — must redirect to / instead"
        }
    },

    # ── NEW: Exception Swallowing ──────────────────────────────────────
    {
        "id": "CANOP-EXC-001",
        "pattern": r"""except\s+(?:Exception|BaseException)\s*(?::\s*$|as\s+\w+\s*:\s*$)""",
        "severity": "LOW",
        "confidence": "LOW",
        "category": "code-quality",
        "langs": {".py"},
        "message": "Broad exception catch (Exception/BaseException) — may hide security errors",
        "cwe": "CWE-755",
        "fix": "Catch specific exceptions or log the error before suppressing",
        "skip_in_strings": True,
        "prescription": {
            "task": "Replace broad exception catch with specific exception types",
            "vulnerability": "Catching Exception or BaseException silently can hide critical security errors: authentication failures, permission denials, cryptographic errors, and injection attempts all raise exceptions that would be swallowed",
            "fix_strategy": "Catch the specific exception type you expect, or at minimum log the exception before suppressing it",
            "fix_patterns": {
                "python": "# Before:\ntry:\n    do_something()\nexcept Exception:\n    pass\n\n# After (option 1 — specific):\ntry:\n    do_something()\nexcept (ValueError, KeyError) as e:\n    logger.warning('Expected error: %s', e)\n\n# After (option 2 — log):\ntry:\n    do_something()\nexcept Exception:\n    logger.exception('Unexpected error')  # at least log it"
            },
            "constraints": [
                "Never use bare 'except:' — always specify at least Exception",
                "Prefer specific exception types (ValueError, KeyError, etc.)",
                "Always log exceptions at WARNING or ERROR level",
                "If suppressing is intentional, add a comment explaining why",
                "Never suppress exceptions in authentication or crypto code"
            ],
            "test_after": "Review all 'except Exception' sites — each should either log the error or catch a specific type"
        }
    },

]

_RULES = _load_rules_from_yaml()
if not _RULES:
    _RULES = _DEFAULT_RULES

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
    rules_loaded = len(_RULES) + len(compiled_rules)
    categories = set()
    for r in _RULES:
        categories.add(r.get("category", "security"))
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
                    "version": "0.2.0",
                    "informationUri": "https://canop.dev",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
