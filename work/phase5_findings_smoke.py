import json

from analysis.findings import EvidenceFindingGenerator
from app.db.base import AnalysisEvidence, EvidenceCategory


def evidence(
    evidence_id: str,
    category: EvidenceCategory,
    evidence_type: str,
    label: str,
    value: dict[str, object],
) -> AnalysisEvidence:
    return AnalysisEvidence(
        id=evidence_id,
        job_id="phase5-smoke",
        category=category,
        evidence_type=evidence_type,
        label=label,
        value_json=json.dumps(value),
        source_path="AndroidManifest.xml",
        source_node="smoke",
    )


def main() -> None:
    items = [
        evidence(
            "flags-1",
            EvidenceCategory.application_flag,
            "application_flags",
            "Application security flags",
            {
                "debuggable": "true",
                "allow_backup": "true",
                "uses_cleartext_traffic": "true",
            },
        ),
        evidence(
            "component-1",
            EvidenceCategory.component,
            "activity",
            ".MainActivity",
            {
                "name": ".MainActivity",
                "component_type": "activity",
                "exported": "true",
                "permission": None,
            },
        ),
        evidence(
            "deeplink-1",
            EvidenceCategory.deep_link,
            "deep_link",
            "demo://example.com/open",
            {"scheme": "demo", "host": "example.com", "path": "/open"},
        ),
        evidence(
            "permission-1",
            EvidenceCategory.permission,
            "dangerous_permission",
            "android.permission.CAMERA",
            {"name": "android.permission.CAMERA", "dangerous": True},
        ),
        evidence(
            "secret-1",
            EvidenceCategory.code_secret,
            "possible_api_key",
            "possible_api_key in Demo.java:12",
            {
                "file": "Demo.java",
                "line": 12,
                "matched_context": "API_KEY=\"AIzaSyDRealisticLookingGoogleKey123456\"",
                "confidence": "high",
            },
        ),
    ]

    findings = EvidenceFindingGenerator().generate(items)
    titles = sorted(finding.title for finding in findings)
    evidence_ids = sorted({evidence_id for finding in findings for evidence_id in finding.evidence_ids})

    print(f"findings={len(findings)}")
    print("titles=" + " | ".join(titles))
    print("evidence_ids=" + ",".join(evidence_ids))


if __name__ == "__main__":
    main()
