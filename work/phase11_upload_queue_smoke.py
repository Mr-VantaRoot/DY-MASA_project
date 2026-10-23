from io import BytesIO
from pathlib import Path
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from app.db.base import AnalysisJob
from app.db.session import SessionLocal


BASE_URL = "http://127.0.0.1:8765"


def make_minimal_zip() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest />")
    return buffer.getvalue()


def wait_for_server() -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE_URL}/api/jobs", timeout=2).read()
            return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("Timed out waiting for smoke-test backend.")


def post_apk(apk_bytes: bytes) -> tuple[int, dict[str, object], float]:
    boundary = f"----codex{uuid.uuid4().hex}"
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="apk"; filename="queue-smoke.apk"\r\n',
            b"Content-Type: application/vnd.android.package-archive\r\n\r\n",
            apk_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    request = urllib.request.Request(
        f"{BASE_URL}/api/jobs",
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=10) as response:
        elapsed = time.perf_counter() - started
        return response.status, json.loads(response.read().decode("utf-8")), elapsed


def main() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = ".;backend"
    process = subprocess.Popen(
        ["python", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8765"],
        cwd=Path.cwd(),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_server()
        status_code, payload, elapsed = post_apk(make_minimal_zip())
        assert status_code == 202, payload
        assert elapsed < 3.0, f"upload response took too long: {elapsed:.2f}s"

        job_id = str(payload["id"])
        stored_path = Path("storage/uploads") / f"{job_id}.apk"
        assert stored_path.exists(), stored_path
        assert stored_path.stat().st_size > 0

        with SessionLocal() as db:
            job = db.get(AnalysisJob, job_id)
            assert job is not None
            assert Path(job.apk_path).exists()

        print(f"upload_status={status_code}")
        print(f"elapsed_seconds={elapsed:.3f}")
        print(f"job_id={job_id}")
        print(f"stored={stored_path}")
    except urllib.error.HTTPError as exc:
        raise AssertionError(exc.read().decode("utf-8")) from exc
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    main()
