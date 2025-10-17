1. Run Symbiotic Security MCP scan on the selected files (or entire workspace if not specified).
   - Prefer a comprehensive scan (code + IaC) when unsure.
   - If the repo is large, ask for scope (paths/globs) before scanning.
2. Aggregate findings with: severity, file path, line, rule ID, CWE (if available), and a minimal code/context snippet.
3. Triage each finding for possible false positives.
   - Mark as false positive only with a brief, concrete rationale (e.g., dead code, test fixture, safe sink, framework auto-escaping).
   - Otherwise keep as a valid issue.
4. Produce a concise report listing only non–false-positive issues.
   - Group by severity (Critical/High/Medium/Low) and category (e.g., Injection, Auth, Crypto, Secrets, Misconfig).
   - For each issue, add 1–2 actionable remediation suggestions.
5. Ask the user if they want automatic remediation now.
   - If yes, propose the exact edit plan (files, lines, changes) and proceed.
   - Apply minimal-risk edits first; avoid breaking APIs; preserve behavior where possible.
6. After applying edits, run linters/tests applicable to the changed files and include any failures in the output.
7. Summarize changes (files modified, key fixes) and provide follow-up recommendations (e.g., add tests, rotate credentials, config hardening).
8. If network access or broader permissions are required for the scan, request them explicitly and proceed once granted.