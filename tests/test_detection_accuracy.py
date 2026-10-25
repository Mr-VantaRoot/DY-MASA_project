from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from analysis.code_risk import CodeRiskEvidenceExtractor
from analysis.evidence import ManifestEvidenceExtractor
from analysis.findings import EvidenceFindingGenerator
from reports.generator import PdfReportGenerator


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

    def test_network_security_config_and_multiple_routes_are_not_overstated(self) -> None:
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">
          <uses-sdk android:targetSdkVersion="33" />
          <application android:networkSecurityConfig="@xml/network_security_config">
            <activity android:name=".Main"><intent-filter>
              <action android:name="android.intent.action.VIEW" />
              <data android:scheme="https" android:host="one.example" />
              <data android:scheme="http" android:host="two.example" />
            </intent-filter></activity>
          </application>
        </manifest>'''
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            (root / "res" / "xml").mkdir(parents=True)
            (root / "res" / "xml" / "network_security_config.xml").write_text(
                '<network-security-config xmlns:android="http://schemas.android.com/apk/res/android"><base-config android:cleartextTrafficPermitted="false" />'
                '<domain-config android:cleartextTrafficPermitted="true"><domain>two.example</domain></domain-config>'
                '</network-security-config>',
                encoding="utf-8",
            )
            evidence = ManifestEvidenceExtractor().extract(root)
        flags = next(item.value for item in evidence if item.evidence_type == "application_flags")
        self.assertIsNone(flags["uses_cleartext_traffic_effective"])
        self.assertEqual(flags["network_security_policy"]["status"], "mixed")
        links = next(item for item in evidence if item.evidence_type == "deep_link")
        # Android merges the two data elements, so both schemes can match
        # both hosts; the declarations are not element-local pairs.
        self.assertEqual(len(links.value["routes"]), 4)
        self.assertEqual(links.value["scope"], "explicit_scheme_host")
        findings = EvidenceFindingGenerator().generate([
            SimpleNamespace(
                id=f"e{index}",
                label=item.label,
                evidence_type=item.evidence_type,
                category=SimpleNamespace(value=item.category.value),
                value_json=item.value_json,
            )
            for index, item in enumerate(evidence)
        ])
        self.assertTrue(any(finding.rule_id == "android-cleartext-policy-uncertain" for finding in findings))
        self.assertFalse(any(finding.rule_id == "android-cleartext-traffic-enabled" for finding in findings))
        self.assertFalse(any(finding.rule_id == "android-wildcard-deep-links-declared" for finding in findings))

    def test_nested_network_policies_inherit_and_mixed_policy_is_explicit(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "res" / "xml").mkdir(parents=True)
            (root / "res" / "xml" / "n.xml").write_text(
                '<network-security-config xmlns:android="http://schemas.android.com/apk/res/android">'
                '<base-config android:cleartextTrafficPermitted="false" />'
                '<domain-config><domain includeSubdomains="true">example.test</domain>'
                '<domain-config android:cleartextTrafficPermitted="true"><domain>api.example.test</domain></domain-config>'
                '</domain-config></network-security-config>', encoding="utf-8"
            )
            policy = ManifestEvidenceExtractor()._network_security_policy(root, "@xml/n", 33)
        self.assertEqual(policy["status"], "mixed")
        self.assertEqual(policy["domain_policies"][0]["cleartext"], "false")
        self.assertTrue(policy["domain_policies"][0]["inherited"])
        self.assertEqual(policy["domain_policies"][1]["cleartext"], "true")
        self.assertFalse(policy["domain_policies"][1]["inherited"])
        self.assertEqual(policy["domain_policies"][1]["parent_domains"], ["example.test"])

    def test_deep_link_constraints_are_merged_without_claiming_ambiguous_routes(self) -> None:
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">
          <application><activity android:name=".Main"><intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <data android:scheme="https" /><data android:scheme="http" />
            <data android:host="*.example.test" /><data android:pathPrefix="/v1" />
            <data android:port="443" /><data android:mimeType="text/plain" />
          </intent-filter></activity></application></manifest>'''
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            link = next(item for item in ManifestEvidenceExtractor().extract(root) if item.evidence_type == "deep_link")
        self.assertEqual({route["scheme"] for route in link.value["routes"]}, {"http", "https"})
        self.assertEqual({route["host"] for route in link.value["routes"]}, {"*.example.test"})
        self.assertEqual({route["path"] for route in link.value["routes"]}, {"/v1"})
        self.assertEqual({route["port"] for route in link.value["routes"]}, {"443"})
        self.assertEqual({route["mime_type"] for route in link.value["routes"]}, {"text/plain"})
        self.assertEqual(link.value["scope"], "wildcard_or_missing_constraint")

    def test_pdf_escapes_untrusted_report_text(self) -> None:
        category = SimpleNamespace(value="runtime")
        evidence = SimpleNamespace(
            id="e1", category=category, evidence_type="runtime", label="<& \"quoted\"",
            source_path="/tmp/<unsafe>.txt", value_json=json.dumps({"result": "observed"}),
        )
        finding = SimpleNamespace(
            id="f1", title="<b>bad & title</b>", severity=SimpleNamespace(value="medium"),
            category="Test", description="description <unsafe> & text", remediation="fix > this",
            evidence_ids_json=json.dumps(["e1"]),
        )
        job = SimpleNamespace(id="pdf-test", original_filename="evil<&.apk", sha256="abc", file_size_bytes=1)
        reasoning = [SimpleNamespace(provider="rule<&", summary="summary <x>", limitations="limits &", attack_paths_json="[]")]
        with TemporaryDirectory() as temp:
            output = PdfReportGenerator().generate(job, [evidence], [finding], reasoning, Path(temp))
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 0)

    def test_pdf_table_keeps_plain_text_entities_readable(self) -> None:
        table = PdfReportGenerator()._table([["Header"], ["A & B < C > D"]])
        self.assertEqual(table._cellvalues[1][0], "A & B < C > D")

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
