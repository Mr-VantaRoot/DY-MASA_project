from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from analysis.code_risk import CodeRiskEvidenceExtractor
from analysis.evidence import EvidenceItem, ManifestEvidenceExtractor, normalize_evidence_items
from app.db.base import EvidenceCategory
from analysis.findings import EvidenceFindingGenerator
from reports.generator import HtmlReportGenerator, PdfReportGenerator


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

    def test_localhost_is_a_low_confidence_development_candidate(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp) / "b3nac" / "injuredandroid"
            root.mkdir(parents=True)
            (root / "Network.java").write_text('String endpoint = "http://localhost:8080/api";\n', encoding="utf-8")
            evidence = CodeRiskEvidenceExtractor().extract(root)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].value["confidence"], "low")
        self.assertEqual(evidence[0].value["ownership"], "first_party_application")
        finding = EvidenceFindingGenerator().generate([
            SimpleNamespace(
                id="e1", label=evidence[0].label, evidence_type=evidence[0].evidence_type,
                category=SimpleNamespace(value=evidence[0].category.value), value_json=evidence[0].value_json,
            )
        ])[0]
        self.assertEqual(finding.severity.value, "info")
        self.assertIn("development", finding.description.lower())

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

    def test_reports_survive_malformed_persisted_json(self) -> None:
        finding = SimpleNamespace(
            id="bad-json-finding", title="Finding", severity=SimpleNamespace(value="info"),
            category="Review", description="Description", remediation="Review.", evidence_ids_json="{bad json",
        )
        job = SimpleNamespace(id="bad-json", original_filename="sample.apk", sha256=None, file_size_bytes=1)
        reasoning = [SimpleNamespace(provider="deterministic", summary="Summary", limitations="Limits", attack_paths_json="not-json")]
        with TemporaryDirectory() as temp:
            root = Path(temp)
            html = HtmlReportGenerator().generate(job, [], [finding], reasoning, root / "html")
            pdf = PdfReportGenerator().generate(job, [], [finding], reasoning, root / "pdf")
            self.assertTrue(html.exists() and pdf.exists())

    def test_pdf_table_keeps_plain_text_entities_readable(self) -> None:
        table = PdfReportGenerator()._table([["Header"], ["A & B < C > D"]])
        self.assertEqual(table._cellvalues[1][0], "A & B < C > D")

    def test_html_report_redacts_workspace_root_from_paths(self) -> None:
        evidence = SimpleNamespace(
            id="e1",
            category=SimpleNamespace(value="manifest"),
            evidence_type="manifest_metadata",
            label="Manifest",
            source_path="/home/mrvantaroot/Android/MASA/storage/workspaces/job/apktool/AndroidManifest.xml",
            value_json=json.dumps({}),
        )
        job = SimpleNamespace(id="html-test", original_filename="sample.apk", sha256="abc", file_size_bytes=1)
        with TemporaryDirectory() as temp:
            output = HtmlReportGenerator().generate(job, [evidence], [], [], Path(temp) / "storage" / "reports")
            html = output.read_text(encoding="utf-8")
        self.assertNotIn("/home/mrvantaroot", html)
        self.assertIn("workspaces/job/apktool/AndroidManifest.xml", html)

    def test_remediation_does_not_embed_raw_evidence_examples(self) -> None:
        remediation = EvidenceFindingGenerator._grounded_remediation(
            "raw_sql_query_construction",
            [],
            "Use parameterized queries.",
        )
        self.assertNotIn("Evidence examples", remediation)
        self.assertFalse(remediation.endswith(".."))

    def test_manifest_to_findings_and_both_reports_preserve_normalized_data(self) -> None:
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">
          <application><receiver android:name="x.TestBroadcastReceiver" android:exported="true" /></application>
        </manifest>'''
        with TemporaryDirectory() as temp:
            root = Path(temp)
            workspace_manifest = root / "storage" / "workspaces" / "job" / "apktool" / "AndroidManifest.xml"
            workspace_manifest.parent.mkdir(parents=True)
            workspace_manifest.write_text(manifest, encoding="utf-8")
            extracted = ManifestEvidenceExtractor().extract(workspace_manifest.parent)
            evidence = [
                SimpleNamespace(
                    id=f"e{index}", category=item.category, evidence_type=item.evidence_type,
                    label=item.label, source_path=str(item.source_path), value_json=item.value_json,
                )
                for index, item in enumerate(extracted)
            ]
            findings = EvidenceFindingGenerator().generate(evidence)
            job = SimpleNamespace(id="report-test", original_filename="sample.apk", sha256="abc", file_size_bytes=1)
            report_dir = root / "storage" / "reports"
            html_path = HtmlReportGenerator().generate(job, evidence, findings, [], report_dir)
            pdf_path = PdfReportGenerator().generate(job, evidence, findings, [], report_dir)
            table = PdfReportGenerator()._evidence_table(evidence, report_dir / "nested")
            source_cell = table._cellvalues[1][3].getPlainText()
            html = html_path.read_text(encoding="utf-8")
            html_exists = html_path.exists()
            pdf_exists = pdf_path.exists()

        self.assertTrue(html_exists and pdf_exists)
        self.assertTrue(any(finding.category == "Exported Components" for finding in findings))
        self.assertIn("broadcast_receiver", html)
        self.assertIn("TestBroadcastReceiver", html)
        self.assertIn("workspaces/job/apktool/AndroidManifest.xml", html)
        self.assertNotIn("/home/mrvantaroot", html)
        self.assertIn("workspaces/job/apktool/AndroidManifest.xml", source_cell)
        self.assertNotIn("/home/mrvantaroot", source_cell)
        self.assertNotIn("Evidence examples", html)

    def test_evidence_register_keeps_all_records_available(self) -> None:
        items = [
            SimpleNamespace(
                id=f"e{index}", category=SimpleNamespace(value="manifest"), evidence_type="record",
                label=f"record-{index}", source_path=f"/tmp/storage/workspaces/job/{index}.xml", value_json="{}",
            )
            for index in range(81)
        ]
        html = HtmlReportGenerator()._evidence(items, Path("/tmp/storage/reports"))
        table = PdfReportGenerator()._evidence_table(items, Path("/tmp/storage/reports"))
        self.assertIn("Showing all 81 normalized persisted evidence records", html)
        self.assertIn("record-80", html)
        self.assertEqual(len(table._cellvalues), 82)

    def test_cross_tool_secret_duplicates_merge_and_keep_source_references(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            value = {"matched_value": "AIza123456789012345678901234567890", "line": 121, "confidence": "high"}
            items = [
                EvidenceItem(EvidenceCategory.code_secret, "possible_api_key", "possible_api_key in strings.xml:121", value, root / "apktool" / "res/values/strings.xml", "line:121"),
                EvidenceItem(EvidenceCategory.code_secret, "possible_api_key", "possible_api_key in strings.xml:121", value, root / "jadx" / "resources/res/values/strings.xml", "line:121"),
            ]
            normalized, counts = normalize_evidence_items(items)
        self.assertEqual(len(normalized), 1)
        self.assertEqual(counts["cross_tool_duplicates_removed"], 1)
        self.assertEqual(counts["same_tool_duplicates_removed"], 0)
        self.assertEqual({item["tool"] for item in normalized[0].value["source_references"]}, {"apktool", "jadx"})

    def test_same_tool_duplicate_is_counted_and_unrelated_records_are_preserved(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            value = {"matched_value": "same-secret", "line": 4}
            items = [
                EvidenceItem(EvidenceCategory.code_secret, "possible_secret", "one", value, root / "apktool" / "a.xml", "line:4"),
                EvidenceItem(EvidenceCategory.code_secret, "possible_secret", "duplicate", value, root / "apktool" / "a.xml", "line:4"),
                EvidenceItem(EvidenceCategory.code_secret, "possible_secret", "different-line", {**value, "line": 5}, root / "apktool" / "a.xml", "line:5"),
                EvidenceItem(EvidenceCategory.code_secret, "possible_secret", "unknown-source", {}, root / "unknown" / "a.xml", None),
            ]
            normalized, counts = normalize_evidence_items(items)
        self.assertEqual(len(normalized), 3)
        self.assertEqual(counts["raw_count"], 4)
        self.assertEqual(counts["normalized_count"], 3)
        self.assertEqual(counts["same_tool_duplicates_removed"], 1)
        self.assertEqual(counts["cross_tool_duplicates_removed"], 0)

    def test_component_type_comes_from_manifest_tag_not_class_name(self) -> None:
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">
          <application><receiver android:name="x.TestBroadcastReceiver" android:exported="true" /></application>
        </manifest>'''
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            item = next(item for item in ManifestEvidenceExtractor().extract(root) if item.category == EvidenceCategory.component)
        self.assertEqual(item.value["component_type"], "broadcast_receiver")
        self.assertEqual(item.value["manifest_tag"], "receiver")

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
