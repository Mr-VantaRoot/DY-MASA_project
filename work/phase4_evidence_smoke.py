from pathlib import Path
import tempfile

from analysis.evidence import ManifestEvidenceExtractor


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.phase4"
    android:versionCode="7"
    android:versionName="1.2.3">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application
        android:allowBackup="true"
        android:debuggable="false"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="demo" android:host="example.com" android:pathPrefix="/open" />
            </intent-filter>
        </activity>
        <service android:name=".SyncService" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="true" />
        <provider android:name=".DataProvider" android:authorities="com.example.phase4.provider" android:exported="false" />
    </application>
</manifest>
"""


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        apktool_dir = Path(temp_dir) / "apktool"
        apktool_dir.mkdir()
        (apktool_dir / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")

        evidence = ManifestEvidenceExtractor().extract(apktool_dir)
        categories = sorted({item.category.value for item in evidence})
        dangerous = [item.label for item in evidence if item.evidence_type == "dangerous_permission"]
        deep_links = [item.label for item in evidence if item.evidence_type == "deep_link"]

        print(f"records={len(evidence)}")
        print(f"categories={','.join(categories)}")
        print(f"dangerous={','.join(dangerous)}")
        print(f"deep_links={','.join(deep_links)}")


if __name__ == "__main__":
    main()
