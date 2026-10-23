# MASA

MASA is an evidence-backed Android static security assessment platform. It accepts an authorized APK, decodes it with apktool, decompiles it with JADX, extracts security evidence, generates deterministic findings, and exports HTML/PDF reports.

DY-MASA adds optional runtime validation through ADB. It supports either a physical Android device or an emulator and records installation, launch, screenshot, logcat, and safe attack-surface validation results. It never wipes, resets, formats, clears, or uninstalls data from the target device; destructive ADB operations are blocked.

## Scope

MASA is an automated static assessment and triage platform. It does not claim to replace a manual mobile penetration tester or prove exploitability. The reasoning layer is deterministic and evidence-constrained; it is not an LLM integration.

## Quick start on Fedora

Install Python, Java, Node.js, PostgreSQL (optional for a local demo), apktool, JADX, and ADB. Configure local paths in `.env` using `.env.example` as a template.

Check the local setup before starting:

```bash
bash work/check-environment.sh
```

Start the backend:

```bash
bash work/start-backend.sh
```

Start the frontend in a second terminal:

```bash
bash work/start-frontend.sh
```

Open `http://127.0.0.1:5173`. The backend health endpoint is available at `http://127.0.0.1:8000/api/health`.

For DY-MASA, enable USB debugging on an authorized test phone, connect it, accept the RSA prompt, and confirm:

```bash
adb devices
```

Detailed operating instructions are in [RUNBOOK.md](RUNBOOK.md). Presentation positioning and limitations are in [TECHNICAL_PRESENTATION_BRIEF.md](TECHNICAL_PRESENTATION_BRIEF.md).
