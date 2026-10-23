import json

from ai.reasoning import DeterministicReasoningEngine
from app.db.base import AnalysisEvidence, AnalysisFinding, EvidenceCategory, FindingSeverity


def evidence(evidence_id: str, label: str) -> AnalysisEvidence:
    return AnalysisEvidence(
        id=evidence_id,
        job_id="phase12-smoke",
        category=EvidenceCategory.component,
        evidence_type="activity",
        label=label,
        value_json=json.dumps({"name": label}),
        source_path="AndroidManifest.xml",
        source_node="activity",
    )


def finding(finding_id: str, title: str, category: str, evidence_id: str) -> AnalysisFinding:
    return AnalysisFinding(
        id=finding_id,
        job_id="phase12-smoke",
        rule_id=finding_id,
        title=title,
        severity=FindingSeverity.medium,
        category=category,
        description=title,
        remediation=f"Remediate {title}.",
        evidence_ids_json=json.dumps([evidence_id]),
    )


def main() -> None:
    evidence_items = [evidence("component-1", ".DeepLinkActivity")]
    findings = [
        finding("finding-1", "Exported activity without permission", "Exported Components", "component-1"),
        finding("finding-2", "Wildcard deep link declared", "Deep Links", "component-1"),
    ]
    result = DeterministicReasoningEngine().reason(findings, evidence_items)
    titles = [path.title for path in result.attack_paths]

    assert titles[0] == "Correlated validation path via .DeepLinkActivity", titles
    assert len(result.attack_paths) == 3, titles
    assert "not confirmed exploit chains" in result.limitations

    print(f"attack_paths={len(result.attack_paths)}")
    print("titles=" + " | ".join(titles))
    print("limitations=" + result.limitations)


if __name__ == "__main__":
    main()
