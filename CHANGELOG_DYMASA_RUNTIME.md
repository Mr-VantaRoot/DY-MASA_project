# DY-MASA runtime hardening changelog

## Stage 1 — logcat accuracy and capture order

- Added pure logcat parsing, PID/UID correlation, tier classification, and target-only crash detection under `dynamic/logcat/`.
- Preserved raw stdout in `logcat.txt`, separated stderr, removed the silent 500-line cap, and added tier artifacts.
- Added isolated marker/clear/action/dump validation steps, accurate `am start` result parsing, and token-aware destructive-ADB blocking.
- Verification: synthetic logcat tests pass. The supplied fixture acceptance counts remain unverified because `tests/fixtures/logcat.txt` and `logcat-filtered.txt` are absent.

## Stage 2 — implicit exports

- Added effective/implicit export and launcher-entry metadata for manifest components.
- Exported-component findings and runtime validation now use effective export semantics; provider review remains strict.
- Verification: manifest and finding tests pass.

## Stage 3 — safety and operational controls

- Added safe device selection, physical-device opt-in, upload-size enforcement, restart cleanup marking, terminal authentication/feature gating, and opt-in personal-storage scanning.
- Verification: safety tests and device-free smoke tests pass. FastAPI `TestClient` could not be used in this environment because requests hang; direct route tests cover the same disabled/authenticated behavior.

## Stage 4 — capture quality and reporting

- Added logcat format fallback and metadata, baseline capture, ADB command auditing, capture metadata, and dynamic validation sections in HTML/PDF reports.
- Verification: tests, device-free smoke tests, and report generation pass. Live-device format samples remain unverified here.

## Stage 5 — honesty and cleanup

- Changed the backend progress message to `Generating rule-based reasoning summary`.
- Relabeled fixed scores as `Heuristic score (not a calculated CVSS vector)`.
- Added `extraction-limits.json` and informational runtime evidence so extractor caps are visible without creating findings.
- Centralized duplicated job storage/report helper methods in `JobService`/`JobRunner`.
- Existing user-facing “AI” labels were intentionally not renamed pending approval.
- Verification: 14 project tests and all available device-free phase 4, 5, 6, 7, 9, 10, 12, and 13 smoke scripts pass.

## Verification limitations

- The exact user-requested system-Python test command is incompatible with the installed Python 3.14/SQLAlchemy combination; the project Python 3.12 environment passes.
- The frontend build must be run from `frontend/`, not the repository root.
