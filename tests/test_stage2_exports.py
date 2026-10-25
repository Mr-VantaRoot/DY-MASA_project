from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from analysis.evidence import ManifestEvidenceExtractor
from analysis.findings import EvidenceFindingGenerator


class Stage2ExportTests(unittest.TestCase):
    def test_effective_export_defaults_and_launcher_metadata(self) -> None:
        manifest = '''
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">
          <application>
            <activity android:name=".Implicit" />
            <activity android:name=".Filtered">
              <intent-filter><action android:name="example.ACTION" /></intent-filter>
            </activity>
            <activity android:name=".Launcher">
              <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
              </intent-filter>
            </activity>
            <activity android:name=".ExplicitFalse" android:exported="false">
              <intent-filter><action android:name="example.ACTION" /></intent-filter>
            </activity>
            <provider android:name=".Provider" android:authorities="example.provider" />
          </application>
        </manifest>
        '''
        with TemporaryDirectory() as temp:
            manifest_path = Path(temp) / "AndroidManifest.xml"
            manifest_path.write_text(manifest, encoding="utf-8")
            records = ManifestEvidenceExtractor().extract(Path(temp))

        components = {record.value["name"]: record.value for record in records if record.evidence_type in {"activity", "content_provider"}}
        self.assertFalse(components[".Implicit"]["exported_effective"])
        self.assertTrue(components[".Filtered"]["exported_effective"])
        self.assertTrue(components[".Filtered"]["exported_implicit"])
        self.assertTrue(components[".Launcher"]["exported_effective"])
        self.assertTrue(components[".Launcher"]["launcher_entry"])
        self.assertFalse(components[".ExplicitFalse"]["exported_effective"])
        self.assertFalse(components[".Provider"]["exported_effective"])

    def test_launcher_is_informational_not_unprotected_export(self) -> None:
        def evidence(identifier: str, value: dict[str, object]) -> SimpleNamespace:
            return SimpleNamespace(
                id=identifier,
                label=str(value["name"]),
                evidence_type="activity",
                category=SimpleNamespace(value="component"),
                value_json=json.dumps(value),
            )

        launcher = evidence("launcher", {
            "name": ".MainActivity",
            "component_type": "activity",
            "exported": None,
            "exported_effective": True,
            "exported_implicit": True,
            "launcher_entry": True,
        })
        implicit = evidence("implicit", {
            "name": ".OtherActivity",
            "component_type": "activity",
            "exported": None,
            "exported_effective": True,
            "exported_implicit": True,
            "launcher_entry": False,
        })
        findings = EvidenceFindingGenerator()._exported_component_findings([launcher, implicit])
        titles = [finding.title for finding in findings]
        self.assertTrue(any("launcher entry point" in title for title in titles))
        self.assertTrue(any("without component-level permission" in title for title in titles))
        unprotected = next(finding for finding in findings if "without component-level permission" in finding.title)
        self.assertNotIn(".MainActivity", unprotected.description)

    def test_api31_missing_exported_is_installation_issue_not_external_exposure(self) -> None:
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">
          <uses-sdk android:targetSdkVersion="31" />
          <application><activity android:name=".NeedsAttribute">
            <intent-filter><action android:name="example.ACTION" /></intent-filter>
          </activity></application>
        </manifest>'''
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            evidence = ManifestEvidenceExtractor().extract(root)
        component = next(item for item in evidence if item.evidence_type == "activity")
        self.assertTrue(component.value["exported_implicit"])
        self.assertTrue(component.value["exported_installation_invalid"])
        self.assertFalse(component.value["exported_effective"])
        component_evidence = [SimpleNamespace(
            id="api31-component",
            label=component.label,
            evidence_type=component.evidence_type,
            category=SimpleNamespace(value="component"),
            value_json=json.dumps(component.value),
        )]
        findings = EvidenceFindingGenerator().generate(component_evidence)
        self.assertTrue(any(finding.category == "Manifest Compatibility" for finding in findings))
        self.assertFalse(any(finding.rule_id.startswith("android-exported-activity") for finding in findings))


if __name__ == "__main__":
    unittest.main()
