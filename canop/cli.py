import click
import json
import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.columns import Columns
from canop.scanner import run_scan, export_sarif

console = Console()

@click.group()
@click.version_option(version="0.2.0", prog_name="canop")
def cli():
    """CanoP — AI Code Security Scanner

    Scan your code for security vulnerabilities.
    """
    pass



@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--sarif', 'sarif_file', default=None, help='Export results as SARIF to this file')
@click.option('--json-out', 'json_file', default=None, help='Export results as JSON to this file')
@click.option('--changed', is_flag=True, default=False, help='Only scan files changed in git (staged + unstaged + untracked)')
@click.option('--fail-on', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], case_sensitive=False), default=None, help='Exit with code 1 if findings at this severity or above exist (for CI/CD)')
@click.option('--min-score', type=int, default=None, help='Exit with code 1 if security score is below this threshold (for CI/CD)')
@click.option('--prescriptions', 'rx_file', default=None, help='Export AI fix prescriptions as JSON to this file')
@click.option('--all', 'show_all', is_flag=True, default=False, help='Show all findings without capping output')
@click.option('--limit', type=int, default=50, help='Maximum number of findings to display in table (default: 50)')
def scan(path, sarif_file, json_file, changed, fail_on, min_score, rx_file, show_all, limit):
    """Scan a directory for security vulnerabilities"""
    
    try:
        
        if changed:
            console.print(f"\n[bold cyan]> Scanning changed files in [white]{os.path.abspath(path)}[/white]...[/bold cyan]\n")
        else:
            console.print(f"\n[bold cyan]> Scanning [white]{os.path.abspath(path)}[/white]...[/bold cyan]\n")

        # Run with progress spinner
        with Progress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[dim]{task.description}[/dim]"),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("Scanning files...", total=None)
            def on_file(rel_path):
                progress.update(task, description=f"Scanning {rel_path}")
            results = run_scan(path, changed_only=changed, on_file=on_file)

        findings = results['findings']
        sev = results['severity_counts']
        grade = results.get('security_grade', 'A+')
        score = results.get('security_score', 100)

        # ── Security Score banner ──────────────────────────────────
        grade_colors = {"A+": "bold green", "A": "green", "B": "cyan", "C": "yellow", "D": "red", "F": "bold red"}
        grade_color = grade_colors.get(grade, "white")

        score_text = Text()
        score_text.append("  SECURITY SCORE\n\n", style="bold white")
        score_text.append(f"  {grade}", style=f"{grade_color}")
        score_text.append(f"  {score}/100\n", style="dim")

        grade_border = "green" if grade in ("A+", "A") else "cyan" if grade == "B" else "yellow" if grade == "C" else "red"
        console.print(Panel(score_text, border_style=grade_border, width=30))

        # ── Summary panel ──────────────────────────────────────────
        summary_text = Text()
        summary_text.append(f"Files scanned : {results['files_scanned']}\n")
        summary_text.append(f"Lines scanned : {results['lines_scanned']:,}\n")
        rule_count = results.get('rules_loaded', 0)
        category_count = results.get('category_count', 0)
        engine = results.get('engine', 'semgrep')
        if engine == 'semgrep+ast':
            summary_text.append(f"Engine        : Semgrep (AST + pattern)\n")
        else:
            summary_text.append(f"Engine        : Semgrep\n")
        summary_text.append(f"Rules loaded  : {rule_count} patterns across {category_count} categories\n")
        summary_text.append(f"Duration      : {results['duration_ms']}ms\n")
        summary_text.append(f"Findings      : {len(findings)}\n")
        if results.get('files_skipped_ignore', 0) > 0:
            summary_text.append(f"Ignored       : {results['files_skipped_ignore']} files (.canopignore)\n")
        if results.get('changed_only'):
            summary_text.append(f"Mode          : changed files only (git diff)\n")
        summary_text.append("\n")

        color_map = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = sev.get(level, 0)
            if count:
                summary_text.append(f"  {level:<10} ", style=color_map[level])
                summary_text.append(f"{count}\n")

        console.print(Panel(summary_text, title=f"[bold]Scan {results['scan_id']}[/bold]", border_style="cyan"))

        # ── Detailed findings table ────────────────────────────────
        # ── Category display names ────────────────────────────────
        _CATEGORY_LABELS = {
            "injection": "Injection",
            "sql-injection": "SQL Injection",
            "secrets": "Secret Leak",
            "crypto": "Weak Crypto",
            "deserialization": "Deserialization",
            "xss": "XSS",
            "path-traversal": "Path Traversal",
            "configuration": "Misconfiguration",
            "auth": "Auth Weakness",
            "ssrf": "SSRF",
            "information-exposure": "Info Exposure",
            "dos": "DoS",
            "timing-attack": "Timing Attack",
            "miscellaneous": "Miscellaneous",
            "code-quality": "Code Quality",
        }

        if findings:
            table = Table(title="Findings", border_style="red", show_lines=True)
            table.add_column("#", style="dim", width=4)
            table.add_column("Severity", width=10)
            table.add_column("Attack", style="cyan", width=16)
            table.add_column("File", style="white", no_wrap=True, overflow="fold")
            table.add_column("Line", justify="right", width=5)
            table.add_column("Description", max_width=50)

            for i, f in enumerate(findings, 1):
                sev_style = color_map.get(f['severity'], "white")
                attack_label = _CATEGORY_LABELS.get(f.get('category', ''), f['rule_id'])
                table.add_row(
                    str(i),
                    f"[{sev_style}]{f['severity']}[/{sev_style}]",
                    f"{attack_label}\n[dim]{f['rule_id']}[/dim]",
                    f['path'],
                    str(f['line']),
                    f['message'],
                )
                if not show_all and i >= limit:
                    break

            console.print(table)

            if not show_all and len(findings) > limit:
                console.print(f"[dim]  ... and {len(findings) - limit} more findings[/dim]\n")

            # Show fix hints for ALL findings (deduplicated by rule)
            if findings:
                console.print("\n[bold yellow]Fix Recommendations:[/bold yellow]")
                shown_rules = set()
                for f in findings:
                    if f['rule_id'] not in shown_rules and f.get('fix_hint'):
                        sev = f['severity']
                        sev_color = color_map.get(sev, 'white')
                        attack_label = _CATEGORY_LABELS.get(f.get('category', ''), f['rule_id'])
                        console.print(f"  [{sev_color}]{sev}[/{sev_color}] [cyan]{attack_label}[/cyan] [dim]({f['rule_id']})[/dim]: {f['fix_hint']}")
                        shown_rules.add(f['rule_id'])
        else:
            console.print("[bold green][SUCCESS] No vulnerabilities found. Your code is secure.[/bold green]")

        # ── Export options ──────────────────────────────────────────
        if sarif_file:
            sarif = export_sarif(results)
            with open(sarif_file, 'w', encoding='utf-8') as f:
                json.dump(sarif, f, indent=2)
            console.print(f"[green]SARIF report saved to {sarif_file}[/green]")

        if json_file:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"[green]JSON report saved to {json_file}[/green]")

        # ── Prescriptions export ───────────────────────────────────
        if rx_file and findings:
            prescriptions = []
            seen_rules = {}  # rule_id -> list of locations
            for f_item in findings:
                rid = f_item['rule_id']
                loc = {"file": f_item['path'], "line": f_item['line'], "snippet": f_item.get('snippet', '')}
                if rid not in seen_rules:
                    seen_rules[rid] = {
                        "rule_id": rid,
                        "severity": f_item['severity'],
                        "category": f_item.get('category', ''),
                        "cwe": f_item.get('cwe'),
                        "message": f_item['message'],
                        "fix_hint": f_item.get('fix_hint'),
                        "prescription": f_item.get('prescription'),
                        "locations": [],
                    }
                seen_rules[rid]["locations"].append(loc)

            for rid, data in seen_rules.items():
                # Build a complete AI-ready prompt for each rule
                locations_str = "\n".join(
                    f"  - {loc['file']}:{loc['line']}"
                    + (f"  |  {loc['snippet'].strip()}" if loc.get('snippet', '').strip() else "")
                    for loc in data["locations"]
                )

                # Use the existing prescription if available, otherwise auto-generate
                existing_rx = data.get("prescription")
                if existing_rx and isinstance(existing_rx, dict):
                    prompt = (
                        f"SECURITY FIX REQUIRED: {existing_rx.get('task', data['message'])}\n"
                        f"Severity: {data['severity']} | CWE: {data.get('cwe', 'N/A')}\n"
                        f"Rule: {rid}\n\n"
                        f"Vulnerability: {existing_rx.get('vulnerability', data['message'])}\n\n"
                        f"Affected locations:\n{locations_str}\n\n"
                        f"Fix strategy: {existing_rx.get('fix_strategy', data.get('fix_hint', 'See below'))}\n"
                    )
                    if existing_rx.get("fix_patterns"):
                        prompt += "\nReference fix patterns:\n"
                        for lang, pattern in existing_rx["fix_patterns"].items():
                            prompt += f"  [{lang}]\n  {pattern}\n"
                    if existing_rx.get("constraints"):
                        prompt += "\nConstraints:\n"
                        for c in existing_rx["constraints"]:
                            prompt += f"  - {c}\n"
                    if existing_rx.get("test_after"):
                        prompt += f"\nValidation: {existing_rx['test_after']}\n"
                else:
                    prompt = (
                        f"SECURITY FIX REQUIRED: {data['message']}\n"
                        f"Severity: {data['severity']} | CWE: {data.get('cwe', 'N/A')}\n"
                        f"Rule: {rid}\n\n"
                        f"Affected locations:\n{locations_str}\n\n"
                    )
                    if data.get("fix_hint"):
                        prompt += f"Recommended fix: {data['fix_hint']}\n\n"
                    prompt += (
                        "Instructions:\n"
                        "1. Open each file listed above and navigate to the specified line\n"
                        "2. Apply the recommended fix while preserving existing functionality\n"
                        "3. Ensure no regressions are introduced\n"
                        "4. Test that the vulnerability is resolved\n"
                    )

                prescriptions.append({
                    "rule_id": rid,
                    "severity": data["severity"],
                    "category": data.get("category", ""),
                    "cwe": data.get("cwe"),
                    "locations": data["locations"],
                    "prompt": prompt,
                })

            rx_output = {
                "canop_version": "0.2.0",
                "scan_id": results['scan_id'],
                "total_prescriptions": len(prescriptions),
                "instruction": "Each prescription below contains a 'prompt' field. Paste it directly into your AI coding assistant (Claude, Copilot, Cursor, ChatGPT) to generate the fix.",
                "prescriptions": prescriptions,
            }
            with open(rx_file, 'w', encoding='utf-8') as f:
                json.dump(rx_output, f, indent=2)
            console.print(f"[green]Prescriptions saved to {rx_file} ({len(prescriptions)} fixes)[/green]")
        elif rx_file and not findings:
            console.print(f"[dim]No findings — no prescriptions to export[/dim]")

        # ── Prescription teaser ─────────────────────────────────────
        if findings and not rx_file:
            unique_rules = len(set(f_item['rule_id'] for f_item in findings))
            console.print(f"\n[bold cyan]> {unique_rules} AI fix prescriptions available.[/bold cyan] Use [white]--prescriptions fixes.json[/white] to export them.")

        # ── CI/CD exit codes ───────────────────────────────────────
        _SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        if fail_on:
            threshold = _SEV_RANK.get(fail_on.upper(), 0)
            for f_item in findings:
                if _SEV_RANK.get(f_item['severity'], 0) >= threshold:
                    console.print(f"\n[bold red][ERROR] CI FAILED: found {f_item['severity']} finding (--fail-on {fail_on.upper()})[/bold red]")
                    raise SystemExit(1)
        if min_score is not None and score < min_score:
            console.print(f"\n[bold red][ERROR] CI FAILED: score {score} < minimum {min_score} (--min-score {min_score})[/bold red]")
            raise SystemExit(1)
            
    except SystemExit:
        raise
    except (OSError, ValueError, RuntimeError) as e:
        console.print(f"[bold red][ERROR] Scan failed: {e}[/bold red]")



_DEFAULT_CANOPIGNORE = """# .canopignore - files and directories to skip during CanoP scans
# Uses glob patterns (same syntax as .gitignore)

# Dependencies
node_modules/
vendor/
venv/
.venv/
__pycache__/
*.egg-info/

# Build outputs
dist/
build/
out/
target/
*.min.js
*.bundle.js

# Test fixtures & snapshots
**/__snapshots__/
**/fixtures/
**/testdata/

# Generated / lock files
package-lock.json
yarn.lock
poetry.lock
Pipfile.lock
go.sum

# IDE & OS
.idea/
.vscode/
*.swp
.DS_Store
Thumbs.db
"""

_DEFAULT_CANOP_YML = """# .canop.yml  –  CanoP project configuration
# Docs: https://canop.dev/docs/config

# Minimum security grade to pass CI (A+, A, B, C, D, F)
min_grade: B

# Severities to treat as failures
fail_on:
  - CRITICAL
  - HIGH

# Extra ignore patterns (merged with .canopignore)
ignore:
  - "docs/**"

# Max findings before non-zero exit code (0 = unlimited)
max_findings: 0
"""


@cli.command()
@click.option('--force', is_flag=True, help='Overwrite existing config files')
def init(force):
    """Initialize CanoP in the current project"""
    import os
    created = []
    skipped = []

    for name, content in [('.canopignore', _DEFAULT_CANOPIGNORE),
                          ('.canop.yml', _DEFAULT_CANOP_YML)]:
        path = os.path.join(os.getcwd(), name)
        if os.path.exists(path) and not force:
            skipped.append(name)
        else:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            created.append(name)

    console.print()
    if created:
        for name in created:
            console.print(f"  [green][INFO][/green] Created [cyan]{name}[/cyan]")
    if skipped:
        for name in skipped:
            console.print(f"  [dim][SKIP] {name} already exists (use --force to overwrite)[/dim]")
    console.print()
    console.print("[green][SUCCESS] CanoP initialized![/green] Run [cyan]canop scan .[/cyan] to get started.")


if __name__ == '__main__':
    cli()
