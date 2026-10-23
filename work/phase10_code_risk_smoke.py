from pathlib import Path
import json
import tempfile

from analysis.code_risk import CodeRiskEvidenceExtractor
from analysis.findings import EvidenceFindingGenerator
from app.db.base import AnalysisEvidence


SOURCE = """
class DemoRisk {
    void configure(android.webkit.WebView webView) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
        webView.addJavascriptInterface(new Bridge(), "bridge");
        String endpoint = "http://api.example.test/v1/login";
        javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        db.rawQuery("SELECT * FROM users WHERE name=" + userInput, null);
    }
}
"""


TRUST_MANAGER = """
class TrustAllManager implements javax.net.ssl.X509TrustManager {
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
}
"""


def persist(item, index: int) -> AnalysisEvidence:
    return AnalysisEvidence(
        id=f"risk-{index}",
        job_id="phase10-smoke",
        category=item.category,
        evidence_type=item.evidence_type,
        label=item.label,
        value_json=json.dumps(item.value),
        source_path=str(item.source_path),
        source_node=item.source_node,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir) / "jadx"
        root.mkdir()
        (root / "DemoRisk.java").write_text(SOURCE, encoding="utf-8")
        (root / "TrustAllManager.java").write_text(TRUST_MANAGER, encoding="utf-8")
        (root / "res" / "layout").mkdir(parents=True)
        (root / "res" / "layout" / "activity.xml").write_text(
            '<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" />',
            encoding="utf-8",
        )
        (root / "com" / "google" / "crypto" / "tink").mkdir(parents=True)
        (root / "com" / "google" / "crypto" / "tink" / "Library.java").write_text(
            'class Library { String hash = "SHA1"; }',
            encoding="utf-8",
        )

        evidence_items = CodeRiskEvidenceExtractor().extract(root)
        persisted = [persist(item, index) for index, item in enumerate(evidence_items, start=1)]
        findings = EvidenceFindingGenerator().generate(persisted)

        evidence_types = sorted({item.evidence_type for item in evidence_items})
        finding_titles = sorted(finding.title for finding in findings)

        assert "insecure_webview_javascript" in evidence_types, evidence_types
        assert "insecure_webview_file_access" in evidence_types, evidence_types
        assert "webview_javascript_bridge" in evidence_types, evidence_types
        assert "cleartext_http_endpoint" in evidence_types, evidence_types
        assert "weak_crypto_mode" in evidence_types, evidence_types
        assert "raw_sql_query_construction" in evidence_types, evidence_types
        assert "trust_all_ssl" in evidence_types, evidence_types
        assert all("schemas.android.com" not in item.value["matched_context"] for item in evidence_items)
        assert all("Library.java" not in item.label for item in evidence_items)
        assert any("HTTP endpoint" in title for title in finding_titles), finding_titles
        assert any("JavaScript bridge" in title for title in finding_titles), finding_titles

        print(f"code_risk_evidence={len(evidence_items)}")
        print("evidence_types=" + ",".join(evidence_types))
        print(f"code_risk_findings={len(findings)}")
        print("finding_titles=" + " | ".join(finding_titles))


if __name__ == "__main__":
    main()
