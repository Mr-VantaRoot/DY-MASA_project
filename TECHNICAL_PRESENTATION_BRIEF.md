# Technical Presentation Brief

## Honest One-Sentence Description

This project is a local Android security assessment platform that uploads an APK, reverse engineers it with real tools, extracts evidence, generates rule-based findings, optionally performs bounded ADB runtime validation, and exports an evidence-backed report.

It is not a full autonomous mobile penetration testing system yet.

## What Actually Happens To An APK

1. The user uploads an `.apk` file through the React dashboard.
2. The FastAPI backend validates that the file is a real APK/ZIP container.
3. An analysis job is created in PostgreSQL when available, or in the supported local SQLite fallback.
4. The backend stores the APK locally under `storage/uploads`.
5. The backend creates a per-job workspace under `storage/workspaces/{job_id}`.
6. The backend calculates the APK SHA-256 hash.
7. `apktool` is executed to decode the APK manifest and resources.
8. `JADX` CLI is executed to decompile Dalvik bytecode into Java-like source where possible.
9. Evidence extractors read the decoded/decompiled output.
10. Rule-based analyzers turn selected evidence into findings.
11. A deterministic reasoning layer groups the findings into a structured summary.
12. HTML and PDF reports are generated and stored under `storage/reports`.

## Real Reverse Engineering Tools Used

The project uses real reverse engineering tools:

- `apktool` for decoding APK resources and `AndroidManifest.xml`
- `JADX` CLI for decompiling code into Java-like source
- Ghidra headless, optionally, for native-library coverage and per-library analysis status
- Python analysis modules for extracting evidence from decoded/decompiled files

The app does not invent decompiled content. If apktool or JADX cannot decode something, the job records the tool failure or continues only when partial output is still useful.

## Evidence Currently Extracted

The current MVP extracts:

- Android manifest metadata
- requested permissions
- dangerous permission classification
- exported activities
- exported services
- exported broadcast receivers
- exported content providers
- deep links and wildcard deep links
- debuggable flag
- backup flag
- cleartext traffic flag
- network security config reference
- FileProvider-like provider declarations
- high-confidence hardcoded secret candidates from actual values
- code-level risk patterns from decompiled source/resources

The code-risk analyzer currently checks for:

- cleartext HTTP endpoints
- WebView JavaScript enablement
- WebView file access enablement
- JavaScript bridge exposure
- TLS trust-management code that requires review
- weak crypto primitives or modes such as AES/ECB, DES, MD5, and SHA-1
- raw SQL query construction candidates

## Important Scanner Improvement

Earlier versions had a weak keyword scanner that could flag resource names like `password_toggle`.

That has been fixed.

The scanner now avoids generated resource files such as:

- `attrs.xml`
- `public.xml`
- `ids.xml`
- `integers.xml`
- `styles.xml`
- `avd_*.xml`
- `$avd_*.xml`

For XML files, it scans actual values, not resource names. It also requires realistic secret shape, such as:

- Google API key prefix like `AIza...`
- Firebase app ID shape
- Stripe-style key prefix
- long high-entropy values when paired with a relevant secret hint

Low-confidence keyword-only evidence is no longer promoted as a main finding.

## How Findings Are Generated

Findings are deterministic and rule-based.

Examples:

- If `android:debuggable="true"` is found, the app reports a debuggable-build finding.
- If exported components are found without permission protection, they are grouped into an exported-component finding.
- If wildcard deep links are found, they are reported as weakly scoped deep links.
- If a value-shaped API key is found, it is reported as a possible hardcoded secret candidate.
- If insecure implementation patterns are found in decompiled code, they are grouped into code-risk findings.

Each finding links back to extracted evidence IDs. The report should not contain unsupported vulnerabilities.

## What The Reasoning Layer Currently Is

The current reasoning layer is intentionally deterministic.

It is called `deterministic-structured-summary`.

It does not call Ollama or another LLM. It summarizes findings, creates validation paths, and explains limitations using deterministic logic.

This was done intentionally because adding an LLM before improving evidence quality would make the output sound confident without making it more correct.

## What This MVP Can Defend In Front Of Experts

This MVP can defend the following claims:

- It uses real APK reverse engineering tools.
- It stores and tracks analysis jobs.
- It extracts real evidence from APK-derived files.
- It generates findings only from stored evidence.
- It exports HTML and PDF reports.
- It is honest about static-analysis limitations.
- It is designed so a future LLM or Ollama module could be added behind the reasoning interface, without making that a dependency of the current platform.

## What This MVP Cannot Honestly Claim

Do not claim these:

- It performs full mobile penetration testing.
- It confirms exploitability.
- It performs a complete autonomous dynamic penetration test.
- It exploits SQL injection, XSS, RCE, or deeplink vulnerabilities.
- It bypasses root/debugger detection.
- It proves secrets are live/valid.
- It replaces a human mobile pentester.

## Correct Way To Present It

Say:

> This is an evidence-backed Android security assessment MVP. It uses apktool and JADX to extract real APK evidence, applies deterministic security rules, optionally validates selected runtime behavior through ADB, and generates a professional report. The reasoning layer is deterministic; it does not depend on an LLM to invent findings.

Do not say:

> This is a fully autonomous AI pentester.

## Expert Questions And Honest Answers

### Is this a pentest?

Not fully. It is a static assessment pipeline that supports pentesting. It identifies attack surface and candidate risks, then tells the tester what to validate manually.

### Does it use real reverse engineering?

Yes. It runs apktool and JADX against the uploaded APK and analyzes their output.

### Does the reasoning layer find vulnerabilities?

Not yet. The current reasoning layer is deterministic. It summarizes and prioritizes rule-generated findings. A future LLM can reason over the same evidence, but it should still be evidence-constrained.

### Can it detect SQL injection or XSS?

It can optionally install and launch an authorized APK on a ready emulator or explicitly permitted physical device and collect bounded runtime observations. That is not comprehensive dynamic testing. SQL injection, XSS, and similar claims still require deeper data-flow analysis and manual/runtime validation.

### Why not add Ollama now?

Because an LLM would not fix poor evidence. The safer architecture is: extract reliable evidence first, then let the LLM explain, correlate, and guide validation.

### How do you prevent fake findings?

Findings are generated only from stored evidence records. Each finding carries evidence IDs that point back to APK-derived files.

### What are the next technical improvements?

The current code-risk analyzer already covers the listed pattern families. The
next improvements are deeper data-flow validation, broader Android-version
runtime coverage, and stronger correlation between static candidates and
authorized runtime observations:

- trace attacker-controlled input into sensitive sinks
- validate WebView navigation and JavaScript-bridge context
- expand runtime coverage without claiming exploitability from reachability
- improve native-code findings beyond Ghidra coverage reporting

## Strong Closing Statement

This MVP is not finished as a full pentest agent, but it demonstrates the correct foundation: real reverse engineering, evidence storage, deterministic findings, honest limitations, and a report pipeline that can later support AI-guided mobile security validation.
