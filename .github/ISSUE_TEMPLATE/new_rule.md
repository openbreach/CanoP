---
name: New Rule / Rule Fix
about: Submit a new YAML rule or fix a false positive/negative
title: "[RULE] "
labels: rule, good first issue
assignees: ''

---

**Is this a new rule or fixing an existing rule?**
- [ ] New Rule
- [ ] Fixing False Positive (Flagged safe code)
- [ ] Fixing False Negative (Missed vulnerable code)

**The Vulnerable Code Pattern**
What code is the AI generating that we need to catch?
```javascript
// Paste the vulnerable code here
```

**Proposed YAML Rule (Optional but highly appreciated!)**
If you know how to write the Semgrep rule, paste the YAML snippet here:
```yaml
  - id: canop.new-rule
    pattern: |
      ...
    message: "..."
    severity: WARNING
    languages: [...]
```

**What prompt should the user give their LLM to fix this?**
(e.g., "Use parameterized queries", "Use DOMPurify before setting HTML")