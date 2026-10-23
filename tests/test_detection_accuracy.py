from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from analysis.code_risk import CodeRiskEvidenceExtractor
from analysis.evidence import ManifestEvidenceExtractor
from analysis.findings import EvidenceFindingGenerator


class DetectionAccuracyTests(unittest.TestCase):
    def test_secure_and_permissive_tls_are_distinguished(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Secure.java").write_text(
                "class Secure implements X509TrustManager {\n"
                "  public void checkServerTrusted(X509Certificate[] c, String a) { validator.check(c); }\n"
                "}\n",
                encoding="utf-8",
            )
            secure = CodeRiskEvidenceExtractor().extract(root)
            self.assertFalse(any(item.evidence_type == "trust_all_ssl" for item in secure))
            (root / "Permissive.java").write_text(
                "class Permissive implements X509TrustManager {\n"
                "  public void checkServerTrusted(X509Certificate[] c, String a) { return; }\n"
                "}\n",
                encoding="utf-8",
            )
            permissive = CodeRiskEvidenceExtractor().extract(root)
            self.assertTrue(any(item.evidence_type == "trust_all_ssl" for item in permissive))
            (root / "Hostname.java").write_text(
                "class Hostname implements HostnameVerifier {\n"
                "  public boolean verify(String host, SSLSession session) { return host.equals(\"example.test\"); }\n"
                "}\n",
                encoding="utf-8",
            )
            secure_hostname = CodeRiskEvidenceExtractor().extract(root)
            self.assertEqual(sum(item.evidence_type == "trust_all_ssl" for item in secure_hostname), 1)
            (root / "Hostname.java").write_text(
                "class Hostname implements HostnameVerifier {\n"
                "  public boolean verify(String host, SSLSession session) { return true; }\n"
                "}\n",
                encoding="utf-8",
            )
            permissive_hostname = CodeRiskEvidenceExtractor().extract(root)
            self.assertEqual(sum(item.evidence_type == "trust_all_ssl" for item in permissive_hostname), 2)

    def test_permission_variants_defaults_and_complete_deep_link_filter(self) -> None:
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">
          <uses-sdk android:targetSdkVersion="27" />
          <uses-permission-sdk-23 android:name="android.permission.CAMERA" />
          <uses-permission-sdk-m android:name="android.permission.READ_CONTACTS" />
          <application>
            <activity android:name=".Main">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="https" android:host="example.test" />
                <data android:pathPrefix="/account" />
              </intent-filter>
            </activity>
            <provider android:name=".P" android:authorities="x.p" />
          </application>
        </manifest>'''
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            records = ManifestEvidenceExtractor().extract(root)
        permissions = [record for record in records if record.evidence_type == "dangerous_permission"]
        self.assertEqual({record.value["declaration_tag"] for record in permissions}, {"uses-permission-sdk-23", "uses-permission-sdk-m"})
        flags = next(record.value for record in records if record.evidence_type == "application_flags")
        self.assertEqual(flags["allow_backup_effective"], "true")
        self.assertEqual(flags["uses_cleartext_traffic_effective"], "true")
        links = [record for record in records if record.evidence_type == "deep_link"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].value["scope"], "explicit_scheme_host")
        self.assertEqual(len(links[0].value["data_elements"]), 2)

    def test_incomplete_extraction_coverage_is_visible(self) -> None:
        item = type("Evidence", (), {
            "id": "limits",
            "evidence_type": "extraction_limits",
            "category": type("Category", (), {"value": "runtime"})(),
            "label": "limits",
            "value_json": json.dumps({"code_risk": {"files_skipped_size": 2, "truncated_rules": ["cleartext_http_endpoint"]}}),
        })()
        findings = EvidenceFindingGenerator().generate([item])
        self.assertEqual([finding.rule_id for finding in findings], ["analysis-extraction-coverage-incomplete"])
        self.assertEqual(findings[0].evidence_ids, ["limits"])


if __name__ == "__main__":
    unittest.main()
