# Analysis

Static analysis and reverse engineering modules will live here.

Phase 3 adds apktool/JADX decompilation orchestration. Phase 4 extracts manifest evidence, permissions, components, deep links, and application security flags.

Phase 5 converts persisted evidence into deterministic findings. Findings must cite evidence IDs and must not be generated without matching evidence.

Phase 6 adds deterministic structured reasoning behind a replaceable interface; it does not call an AI or LLM service.

The next phases will add hardcoded secret scanning, Firebase configuration checks, native libraries, certificates, WebView usage, SSL configuration, and reporting.
