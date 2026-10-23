import tempfile
from pathlib import Path

from analysis.evidence import CodeSecretEvidenceExtractor


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        res_values = root / "apktool" / "res" / "values"
        res_drawable = root / "apktool" / "res" / "drawable"

        write(
            res_values / "attrs.xml",
            """
            <resources>
                <attr name="passwordToggleEnabled" format="boolean" />
                <attr name="passwordToggleTint" format="color" />
            </resources>
            """,
        )
        write(
            res_values / "public.xml",
            """
            <resources>
                <public type="id" name="password_toggle" id="0x7f080123" />
                <public type="string" name="firebase_common_keep" id="0x7f120123" />
            </resources>
            """,
        )
        write(
            res_drawable / "$avd_hide_password__0.xml",
            """
            <animated-vector xmlns:android="http://schemas.android.com/apk/res/android"
                android:drawable="@drawable/design_password_eye" />
            """,
        )
        write(
            res_values / "strings.xml",
            """
            <resources>
                <string name="google_api_key">AIzaSyDRealisticLookingGoogleApiKey123456</string>
                <string name="admin_password">CorrectHorseBatteryStaple2026!Demo</string>
                <string name="password_label">Password</string>
            </resources>
            """,
        )

        evidence = CodeSecretEvidenceExtractor().extract(root)
        labels = sorted(item.label for item in evidence)
        values = [item.value for item in evidence]
        high_confidence = [item for item in evidence if item.value.get("confidence") == "high"]

        assert all("attrs.xml" not in label for label in labels), labels
        assert all("public.xml" not in label for label in labels), labels
        assert all("avd_hide_password" not in label for label in labels), labels
        assert any(item.evidence_type == "possible_api_key" for item in evidence), labels
        assert any(item.evidence_type == "possible_password" for item in evidence), labels
        assert all(value.get("confidence") == "high" for value in values), values

        print(f"secret_fixture_total={len(evidence)}")
        print(f"high_confidence={len(high_confidence)}")
        print("labels=" + " | ".join(labels))


if __name__ == "__main__":
    main()
