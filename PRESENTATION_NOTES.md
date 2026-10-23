# Presentation Notes

## How To Position The Project

Do not present this MVP as a complete manual penetration test.

Present it as:

```text
An evidence-backed Android static security assessment platform with an AI-ready reasoning layer.
```

The system performs real APK decompilation, evidence extraction, rule-backed finding generation, structured reasoning, and HTML/PDF reporting.

## What Was Improved After Review

- The report title was changed from penetration testing language to static security assessment language.
- The report now includes explicit scope and limitations.
- Repetitive exported-component findings are grouped.
- Severity rationale is included in finding descriptions.
- MASVS/MSTG mapping and CVSS-style estimates are included in finding descriptions.
- Wildcard or weakly scoped deep links are rated higher than ordinary deep links.
- ContentProvider and FileProvider declarations now trigger review findings where appropriate.
- JADX output is scanned for possible hardcoded secrets, keys, tokens, Firebase config references, and password-like assignments.
- The AI section was renamed to structured risk summary because no real LLM is wired in yet.

## Honest Limitations

- No dynamic testing is performed yet.
- SQL injection, XSS, RCE, weak crypto, debugger bypass, and root bypass findings require deeper code analysis or dynamic validation.
- Code-secret detection is a first-pass triage scanner and requires manual validation.
- Severity values are evidence-based estimates, not final manual pentest ratings.

## Strong Demo Message

The project does not claim exploitability from manifest evidence alone. It separates extracted evidence, rule-backed findings, structured risk summaries, and report generation so future dynamic testing and deeper code analysis can be added cleanly.
