# Contributing to CanoP

First off, thank you for considering contributing to CanoP! 

Since CanoP targets AI-generated code vulnerabilities, **we heavily rely on the community** to help us track the new and creative ways that LLMs write insecure code. 

You **do not need to know Python** to contribute to this project. Our entire scanning engine is driven by simple YAML files.

## Adding a New Security Rule (Takes 5 Minutes)

CanoP stores its Semgrep-compatible rules in `canop/rules/`. The built-in scanner runs locally without requiring the Semgrep CLI; an installed Semgrep CLI can provide AST-based analysis as an additional engine.

If you see an AI generate a vulnerable code pattern, here is how you add a rule to catch it:

1. Look in `canop/rules/` and find the relevant language file (e.g., `js-react.yml`, `python-django.yml`). If a file for your framework doesn't exist, create it!
2. Copy and paste the following template into the file:

```yaml
  - id: canop.your-language.your-rule-name-here
    pattern: |
      <paste the exact insecure code pattern here, e.g., print($VAR)>
    message: >
      <Describe why this is vulnerable>
    severity: <WARNING|ERROR>
    languages: [<javascript|typescript|python|go|etc>]
    metadata:
      canop_severity: <LOW|MEDIUM|HIGH|CRITICAL>
      confidence: <LOW|MEDIUM|HIGH>
      category: <security|best-practice>
      cwe: "CWE-XXX" # Optional
      fix: "<How should the user tell ChatGPT to fix this? e.g., 'Use parameterized queries'>"
```

3. Commit your changes and open a Pull Request!

*Tip: You can use `...` to match any sequence of code, and `$VAR` or `$X` to match any variable name.*

## Python Core Development

If you'd like to contribute to the core CLI engine (`canop/`):

1. Clone the repository.
2. For the CLI, run `pip install -r requirements.txt`.
3. The core scanning logic is located in `canop/scanner.py` and `canop/semgrep_engine.py`.
4. Ensure the tool does not crash and remains an offline-first dependency.
5. Run `python -m unittest discover -s tests -v` before opening a pull request.

## Submitting Pull Requests

- Keep PRs focused on a single feature or rule group.
- If adding a rule, include a small example in the PR description of the vulnerable AI code you are trying to catch.
- Include or update a regression test for behavior changes.
- We aim to acknowledge pull requests within seven days. Review time may be longer for changes to the scanner engine or security-sensitive behavior.