# MASA Runbook

Use only APKs you own or are authorized to test. MASA performs static assessment, not full manual exploit verification.

## Start The Backend

On Fedora/Linux, open a terminal from the project root:

```bash
export PYTHONPATH=".:backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Or use the included Fedora helper, which automatically uses PostgreSQL when it is available and SQLite otherwise:

```bash
bash work/start-backend.sh
```

On Windows PowerShell, use `$env:PYTHONPATH = ".;backend"` instead.

## Start The Frontend

Open a second terminal from the project root:

```bash
cd frontend
npm run dev
```

The equivalent helper is `bash work/start-frontend.sh` from the project root.

Open:

```text
http://127.0.0.1:5173
```

The frontend must show Vite output in the terminal. If you see lines like
`127.0.0.1 - - "GET / HTTP/1.1"`, you are running Python's static file server,
not the Vite dev server.

Before uploading, confirm the backend is reachable:

```bash
curl http://127.0.0.1:8000/api/health
```

If PostgreSQL is not available on a Fedora demo machine, use the local SQLite fallback for the submission demo:

```bash
export MOBILE_PENTEST_DATABASE_URL="sqlite:///./storage/masa.sqlite3"
```

This fallback is intended for a single-user local demo. PostgreSQL remains the normal backend database.

## Run One APK From The CLI

```bash
export PYTHONPATH=".:backend"
python -m app.cli.analyze_apk "C:\path\to\authorized-app.apk"
```

On Fedora/Linux, use an absolute Linux path such as `/path/to/authorized-app.apk`.

## DY-MASA With A Physical Android Phone

On Fedora, install the platform ADB client if it is not already available:

```bash
sudo dnf install android-tools
```

Enable Developer Options and USB debugging on an authorized test phone, connect it by USB, and accept the RSA prompt. Confirm that ADB sees it:

```bash
adb devices
```

The phone is a valid DY-MASA target; an emulator is optional. The runtime installs the APK, launches it, captures a screenshot, collects logcat, and performs safe reachability checks. DY-MASA does not wipe, reset, format, clear, or uninstall personal phone data; its ADB client blocks those destructive operations.

The CLI prints the job status, evidence count, finding count, artifact count, reasoning count, and generated report paths.

## Expected Successful Flow

```text
Upload APK
-> apktool decompilation
-> JADX decompilation
-> optional Ghidra native-library analysis (only when configured and .so files exist)
-> manifest evidence extraction
-> evidence-backed findings
-> deterministic reasoning
-> HTML and PDF reports
```

## Demo Rescue Polish

The dashboard and report now prioritize judge-readable results:

- upload errors are shown in plain English
- low-confidence keyword-only secret hits are not promoted as findings
- the report leads with executive summary, key findings, and manual validation steps
- the evidence register is still available, but it no longer dominates the first view

## Expected Failure Behavior

Invalid APKs should fail honestly during decompilation. The job will keep tool logs in:

```text
storage\workspaces\{job_id}\logs
```

## Optional Ghidra Support

Ghidra is an optional static-analysis stage for native Android libraries. It does not replace JADX or apktool, and a Ghidra run does not by itself create a vulnerability finding.

Set these values in `.env` after installing Ghidra:

```text
MOBILE_PENTEST_GHIDRA_ENABLED=true
MOBILE_PENTEST_GHIDRA_HEADLESS_PATH=C:/ghidra/support/analyzeHeadless.bat
MOBILE_PENTEST_GHIDRA_TIMEOUT_SECONDS=900
```

For APKs without `lib\\*\\*.so` files, MASA records that Ghidra was skipped and continues normally. Ghidra logs and its project summary are stored under:

```text
storage\workspaces\{job_id}\ghidra
storage\workspaces\{job_id}\logs\ghidra.log
```
