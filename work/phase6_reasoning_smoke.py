import json

from ai.reasoning import DeterministicReasoningEngine
from app.db.base import AnalysisEvidence, AnalysisFinding, EvidenceCategory, FindingSeverity


def main() -> None:
    evidence = [
        AnalysisEvidence(
            id="evidence-1",
            job_id="phase6-smoke",
            category=EvidenceCategory.application_flag,
            evidence_type="application_flags",
            label="Application security flags",
            value_json=json.dumps({"debuggable": "true"}),
            source_path="AndroidManifest.xml",
            source_node="application",
        )
    ]
    findings = [
        AnalysisFinding(
            id="finding-1",
            job_id="phase6-smoke",
            rule_id="android-debuggable-enabled",
            title="Application is debuggable",
            severity=FindingSeverity.high,
            category="Application Configuration",
            description="The manifest explicitly enables Android debugging for the application.",
            remediation="Disable android:debuggable for release builds.",
            evidence_ids_json=json.dumps(["evidence-1"]),
        )
    ]

    result = DeterministicReasoningEngine().reason(findings, evidence)
    print(f"provider={result.provider}")
    print(f"summary={result.summary}")
    print(f"attack_paths={len(result.attack_paths)}")
    print(f"evidence_ids={','.join(result.attack_paths[0].evidence_ids)}")


if __name__ == "__main__":
    main()
