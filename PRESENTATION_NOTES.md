# Presentation Notes

## How To Position The Project

Do not present this MVP as a complete manual penetration test.

Present it as:

```text
An evidence-backed Android security assessment platform with deterministic reasoning and an optional, bounded ADB runtime-validation stage.
```

The system performs real APK decompilation, evidence extraction, rule-backed finding generation, structured reasoning, optional native analysis, optional bounded runtime validation, and HTML/PDF reporting.

## What Was Improved After Review

- The report title was changed from penetration testing language to static security assessment language.
- The report now includes explicit scope and limitations.
- Repetitive exported-component findings are grouped.
- Severity rationale is included in finding descriptions.
- MASVS/MSTG mapping and CVSS-style estimates are included in finding descriptions.
- Wildcard or weakly scoped deep links are rated higher than ordinary deep links.
- ContentProvider and FileProvider declarations now trigger review findings where appropriate.
- JADX output is scanned for possible hardcoded secrets, keys, tokens, Firebase config references, and password-like assignments.
- The reasoning section is labelled structured risk summary because no live LLM is wired in.
- Ghidra is optional and off by default; when enabled, native-library coverage is reported per library.
- DY-MASA runtime validation is optional, requires a ready authorized emulator or explicitly permitted physical device, and records failures or partial results honestly.

## Honest Limitations

- Runtime validation is limited to selected install, launch, deep-link, logcat, screenshot, and metadata checks; it is not a full manual or instrumented pentest.
- SQL injection, XSS, RCE, weak crypto, debugger bypass, and root bypass findings require deeper code analysis or dynamic validation.
- Code-secret detection is a first-pass triage scanner and requires manual validation.
- Severity values are evidence-based estimates, not final manual pentest ratings.

## Strong Demo Message

The project does not claim exploitability from manifest evidence alone. It separates extracted evidence, rule-backed findings, structured risk summaries, runtime observations, and report generation. A runtime observation is not proof of exploitability.
