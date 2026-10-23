import json
import pathlib
import subprocess
import time
import urllib.request
import uuid
import zipfile


def wait_for_server() -> None:
    for _ in range(20):
        try:
            urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=3)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Backend did not become ready.")


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    test_apk = root / "work" / "phase2-smoke.apk"
    with zipfile.ZipFile(test_apk, "w") as apk:
        apk.writestr("AndroidManifest.xml", '<manifest package="local.smoke"/>')

    process = subprocess.Popen(
        ["python", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_server()

        boundary = f"----CodexBoundary{uuid.uuid4().hex}"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="apk"; filename="phase2-smoke.apk"\r\n'
            "Content-Type: application/vnd.android.package-archive\r\n\r\n"
        ).encode()
        body += test_apk.read_bytes()
        body += f"\r\n--{boundary}--\r\n".encode()

        request = urllib.request.Request(
            "http://127.0.0.1:8000/api/jobs",
            data=body,
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        created = json.loads(urllib.request.urlopen(request, timeout=30).read().decode())
        print(f"created {created['id']} {created['status']}")

        job = created
        job_url = f"http://127.0.0.1:8000/api/jobs/{created['id']}"
        for _ in range(20):
            time.sleep(1)
            job = json.loads(urllib.request.urlopen(job_url, timeout=30).read().decode())
            if job["status"] in {"completed", "failed"}:
                break

        print(
            json.dumps(
                {
                    "status": job["status"],
                    "progress": job["progress"],
                    "sha256": job["sha256"],
                    "step": job["current_step"],
                },
                indent=2,
            )
        )
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == "__main__":
    main()
