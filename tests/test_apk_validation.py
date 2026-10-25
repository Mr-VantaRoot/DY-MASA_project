from pathlib import Path
from tempfile import TemporaryDirectory
import zipfile
import unittest

from app.services.job_service import JobService


class ApkValidationTests(unittest.TestCase):
    def test_zip_without_manifest_is_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "missing-manifest.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", b"not-a-real-dex")
            error = JobService._apk_validation_error(path, path.stat().st_size)
        self.assertIn("missing AndroidManifest.xml", error or "")

    def test_valid_manifest_member_passes_container_validation(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"binary-or-xml-manifest")
            self.assertIsNone(JobService._apk_validation_error(path, path.stat().st_size))

    def test_corrupt_zip_entry_is_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "corrupt.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                info = archive.getinfo("AndroidManifest.xml")
            data = bytearray(path.read_bytes())
            payload_offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
            data[payload_offset] ^= 0xFF
            path.write_bytes(data)
            error = JobService._apk_validation_error(path, path.stat().st_size)
        self.assertTrue(error and ("valid APK ZIP" in error or "corrupt ZIP" in error))


if __name__ == "__main__":
    unittest.main()
