"""
Python taint analysis for CanoP.

The MVP is intentionally deterministic and intraprocedural: assignments,
string operations, containers, parameters, return values, and calls are
modeled inside each function.  Findings include source/sink evidence and are
kept separate from heuristic rule findings.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class TaintState:
    tainted: bool = False
    origin: Optional[str] = None
    steps: List[dict] = field(default_factory=list)


@dataclass
class TaintFinding:
    rule_id: str
    path: str
    line: int
    col: int
    severity: str
    confidence: str
    category: str
    message: str
    snippet: str
    cwe: str
    fix_hint: str
    source: dict
    sink: dict
    trace: List[dict]


SOURCE_CALLS = {
    "input": "python.stdin",
    "sys.argv": "python.argv",
    "os.environ": "python.environment",
    "os.getenv": "python.environment",
    "flask.request": "http.request",
    "django.request": "http.request",
}

SOURCE_ATTRIBUTES = (
    "request.args",
    "request.values",
    "request.form",
    "request.data",
    "request.json",
    "request.headers",
    "request.cookies",
    "request.GET",
    "request.POST",
    "request.body",
)

SINKS = {
    "eval": ("CANOP-TAINT-CODE-INJECTION", "CRITICAL", "CWE-95",
             "Use ast.literal_eval() or structured parsing"),
    "exec": ("CANOP-TAINT-CODE-INJECTION", "CRITICAL", "CWE-95",
             "Remove exec() and use structured dispatch"),
    "os.system": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                  "Use subprocess.run() with a list and shell=False"),
    "os.popen": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                 "Use subprocess.run() with a list and shell=False"),
    "subprocess.run": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                       "Pass command arguments as a list and keep shell=False"),
    "subprocess.call": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                        "Pass command arguments as a list and keep shell=False"),
    "subprocess.check_call": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                              "Pass command arguments as a list and keep shell=False"),
    "subprocess.check_output": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                                "Pass command arguments as a list and keep shell=False"),
    "subprocess.Popen": ("CANOP-TAINT-COMMAND-INJECTION", "CRITICAL", "CWE-78",
                         "Pass command arguments as a list and keep shell=False"),
    "cursor.execute": ("CANOP-TAINT-SQL-INJECTION", "HIGH", "CWE-89",
                       "Use parameter placeholders and pass values separately"),
    "connection.execute": ("CANOP-TAINT-SQL-INJECTION", "HIGH", "CWE-89",
                           "Use parameter placeholders and pass values separately"),
}


def _dotted_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return None


def _line_snippet(lines: List[str], line: int) -> str:
    start = max(0, line - 2)
    end = min(len(lines), line + 1)
    return "\n".join(lines[start:end])


def _is_shell_true(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value is True
    return False


def _sink_kind(call: ast.Call) -> Optional[Tuple[str, bool]]:
    name = _dotted_name(call.func)
    if name in SINKS:
        return name, name.startswith("subprocess.") or name in {"os.system", "os.popen"}
    if name and name.endswith(".execute"):
        if name.endswith("cursor.execute"):
            return "cursor.execute", False
        return "connection.execute", False
    return None


def _source_state(node: ast.AST) -> Optional[TaintState]:
    name = _dotted_name(node)
    if name:
        if name in SOURCE_CALLS:
            return TaintState(True, SOURCE_CALLS[name])
        if name.startswith("request.") or ".request." in name:
            return TaintState(True, "http.request")
        if any(name == suffix or name.endswith("." + suffix) for suffix in SOURCE_ATTRIBUTES):
            return TaintState(True, "http.request")

    if isinstance(node, ast.Call):
        call_name = _dotted_name(node.func)
        if call_name in {"input", "os.getenv", "sys.argv"}:
            origin = SOURCE_CALLS.get(call_name)
            return TaintState(True, origin)
        if call_name in {"flask.request", "django.request"}:
            return TaintState(True, "http.request")
        if call_name and (
            call_name.startswith("request.")
            or ".request." in call_name
            or call_name.startswith("flask.request.")
            or call_name.startswith("django.request.")
        ):
            return TaintState(True, "http.request")

    if isinstance(node, ast.Attribute):
        if _dotted_name(node).startswith("sys.argv"):
            return TaintState(True, "python.argv")

    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id in {"sys", "argv"}:
            return TaintState(True, "python.argv")

    return None


def _merge_state(*states: Optional[TaintState]) -> TaintState:
    tainted = [state for state in states if state and state.tainted]
    if not tainted:
        return TaintState()
    origin = tainted[0].origin
    steps = []
    for state in tainted:
        steps.extend(state.steps)
    return TaintState(True, origin, steps)


class PythonTaintAnalyzer:
    def analyze_files(self, root: Path, changed_files: Optional[Set[str]] = None) -> List[dict]:
        findings: List[dict] = []
        for path in sorted(root.rglob("*.py")):
            if any(part in {".git", ".venv", "venv", "__pycache__", "build", "dist"} for part in path.parts):
                continue
            rel = path.relative_to(root).as_posix()
            if changed_files is not None and rel not in changed_files:
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue

            lines = source.splitlines()
            for finding in self._analyze_tree(tree, rel, lines):
                findings.append(finding)
        return findings

    def _analyze_tree(self, tree: ast.AST, path: str, lines: List[str]) -> Iterable[dict]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            yield from self._analyze_function(node, path, lines)

        # Module-level analysis catches scripts and top-level Flask handlers.
        yield from self._analyze_statements(
            [node for node in tree.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))],
            path,
            lines,
            {},
        )

    def _analyze_function(
        self,
        function: ast.AST,
        path: str,
        lines: List[str],
    ) -> Iterable[dict]:
        env: Dict[str, TaintState] = {}
        args = getattr(function.args, "args", [])
        args += getattr(function.args, "kwonlyargs", [])
        for arg in args:
            env[arg.arg] = TaintState()

        yield from self._analyze_statements(function.body, path, lines, env)

    def _expression_state(self, node: ast.AST, env: Dict[str, TaintState]) -> TaintState:
        source = _source_state(node)
        if source:
            return source

        if isinstance(node, ast.Name):
            return env.get(node.id, TaintState())
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = _dotted_name(node)
            if isinstance(node, ast.Attribute) and name:
                base_name = name.rsplit(".", 1)[0]
                if base_name in env:
                    return env[base_name]
            if isinstance(node, ast.Subscript):
                return self._expression_state(node.value, env)
            return TaintState()
        if isinstance(node, ast.BinOp):
            return _merge_state(
                self._expression_state(node.left, env),
                self._expression_state(node.right, env),
            )
        if isinstance(node, ast.JoinedStr):
            states = [self._expression_state(value, env) for value in node.values]
            return _merge_state(*states)
        if isinstance(node, ast.FormattedValue):
            return self._expression_state(node.value, env)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _merge_state(*(self._expression_state(item, env) for item in node.elts))
        if isinstance(node, ast.Dict):
            states = []
            for key, value in zip(node.keys, node.values):
                if key:
                    states.append(self._expression_state(key, env))
                states.append(self._expression_state(value, env))
            return _merge_state(*states)
        if isinstance(node, ast.Call):
            states = [self._expression_state(arg, env) for arg in node.args]
            states += [self._expression_state(keyword.value, env) for keyword in node.keywords]
            states.append(self._expression_state(node.func, env))
            return _merge_state(*states)
        if isinstance(node, ast.IfExp):
            return _merge_state(
                self._expression_state(node.body, env),
                self._expression_state(node.orelse, env),
            )
        return TaintState()

    def _analyze_statements(
        self,
        statements: List[ast.stmt],
        path: str,
        lines: List[str],
        env: Dict[str, TaintState],
    ) -> Iterable[dict]:
        for statement in statements:
            if isinstance(statement, ast.Assign):
                state = self._expression_state(statement.value, env)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = state
                    elif isinstance(target, ast.Tuple):
                        for element in target.elts:
                            if isinstance(element, ast.Name):
                                env[element.id] = state
            elif isinstance(statement, ast.AnnAssign) and statement.value:
                state = self._expression_state(statement.value, env)
                if isinstance(statement.target, ast.Name):
                    env[statement.target.id] = state
            elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
                env[statement.target.id] = _merge_state(
                    env.get(statement.target.id, TaintState()),
                    self._expression_state(statement.value, env),
                )
            elif isinstance(statement, ast.Return):
                if statement.value:
                    self._expression_state(statement.value, env)

            yield from self._analyze_node(statement, path, lines, env)

            for child in ast.iter_child_nodes(statement):
                if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                    yield from self._analyze_node(child, path, lines, env)

    def _analyze_node(
        self,
        node: ast.AST,
        path: str,
        lines: List[str],
        env: Dict[str, TaintState],
    ) -> Iterable[dict]:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            sink_info = _sink_kind(child)
            if not sink_info:
                continue

            sink_name, is_shell_sink = sink_info
            argument_states = [
                self._expression_state(argument, env)
                for argument in child.args
            ]

            if sink_name.startswith("subprocess.") or sink_name in {"os.system", "os.popen"}:
                if sink_name.startswith("subprocess.") and not _is_shell_true(child):
                    if len(child.args) == 1 and isinstance(child.args[0], (ast.List, ast.Tuple)):
                        argument_states = [TaintState()]  # arguments are separate, not shell text

            tainted = _merge_state(*argument_states)
            if not tainted.tainted:
                continue

            rule_id, severity, cwe, fix_hint = SINKS[sink_name]
            source_line = getattr(child, "lineno", 1)
            trace = [{
                "kind": "source",
                "origin": tainted.origin,
                "line": source_line,
            }, {
                "kind": "sink",
                "name": sink_name,
                "line": getattr(child, "lineno", 1),
            }]

            yield {
                "rule_id": rule_id,
                "path": path,
                "line": getattr(child, "lineno", 1),
                "col": getattr(child, "col_offset", 0) + 1,
                "severity": severity,
                "confidence": "HIGH" if tainted.origin else "MEDIUM",
                "category": "command-injection" if "COMMAND" in rule_id else "sql-injection",
                "message": "Attacker-controlled data reaches a dangerous sink.",
                "snippet": _line_snippet(lines, getattr(child, "lineno", 1)),
                "cwe": cwe,
                "fix_hint": fix_hint,
                "source": {
                    "kind": tainted.origin or "unknown",
                    "line": getattr(child, "lineno", 1),
                },
                "sink": {
                    "kind": sink_name,
                    "line": getattr(child, "lineno", 1),
                },
                "trace": trace,
                "engine": "taint",
                "taint_mode": "balanced",
            }

