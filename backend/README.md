# Backend

FastAPI backend for MASA.

Phase 1 exposes a health endpoint and verifies required local tooling:

- PostgreSQL
- Java
- apktool
- JADX

Phase 2 adds APK intake and database-backed analysis job tracking.

Phase 3 runs real apktool and JADX decompilation and stores per-job artifact records.

Run locally:

```powershell
$env:PYTHONPATH = "backend"
python -m uvicorn app.main:app --reload
```
