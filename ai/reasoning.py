from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
import json

from app.db.base import AnalysisEvidence, AnalysisFinding


@dataclass(frozen=True)
class AttackPath:
    title: str
    steps: list[str]
    evidence_ids: list[str]


@dataclass(frozen=True)
class ReasoningResult:
    provider: str
    summary: str
    attack_paths: list[AttackPath]
    limitations: str

    @property
    def attack_paths_json(self) -> str:
        return json.dumps(
            [
                {
                    "title": attack_path.title,
                    "steps": attack_path.steps,
                    "evidence_ids": attack_path.evidence_ids,
                }
                for attack_path in self.attack_paths
            ],
            sort_keys=True,
        )


class ReasoningEngine(ABC):
    @abstractmethod
    def reason(self, findings: list[AnalysisFinding], evidence: list[AnalysisEvidence]) -> ReasoningResult:
        raise NotImplementedError


class DeterministicReasoningEngine(ReasoningEngine):
    provider = "deterministic-structured-summary"
    ENTRY_POINT_CATEGORIES = {
        "Exported Components",
        "Deep Links",
        "File Sharing",
        "WebView",
    }

    def reason(self, findings: list[AnalysisFinding], evidence: list[AnalysisEvidence]) -> ReasoningResult:
        evidence_by_id = {item.id: item for item in evidence}
        correlated_paths = self._correlated_validation_paths(findings, evidence_by_id)
        validation_paths = [self._validation_path(finding, evidence_by_id) for finding in findings]
        severity_counts = self._severity_counts(findings)
        summary = self._summary(findings, severity_counts)
        return ReasoningResult(
            provider=self.provider,
            summary=summary,
            attack_paths=correlated_paths + validation_paths,
            limitations=(
                "This section is a structured deterministic summary, not a live LLM analysis. "
                "Correlated paths are based on shared static evidence, such as the same component or entry point "
                "appearing in multiple findings. They are review priorities, not confirmed exploit chains. "
                "The analysis is limited to extracted APK evidence and rule-generated findings; it does not prove exploitability."
            ),
        )

    def _validation_path(
        self,
        finding: AnalysisFinding,
        evidence_by_id: dict[str, AnalysisEvidence],
    ) -> AttackPath:
        evidence_ids = self._evidence_ids(finding)
        cited = self._cited_labels(evidence_ids, evidence_by_id)
        return AttackPath(
            title=f"Validation path for {finding.title}",
            steps=[
                f"Evidence to inspect: {cited}.",
                f"Static risk area: {finding.category}.",
                f"Validation focus: {self._validation_focus(finding)}",
                f"Recommended remediation path: {finding.remediation}",
            ],
            evidence_ids=evidence_ids,
        )

    @staticmethod
    def _validation_focus(finding: AnalysisFinding) -> str:
        if finding.category == "Exported Components":
            return "invoke only the named manifest component and verify authorization, input handling, and sensitive data access"
        if finding.category == "Deep Links":
            return "exercise the cited route constraints and verify authorization and input validation"
        if finding.category == "Code Review":
            return "inspect the cited source locations and determine whether the candidate is active, reachable, and security-sensitive"
        if finding.category == "Network Security":
            return "trace the cited endpoint/configuration into actual transport behavior and test cleartext policy"
        if finding.category == "WebView":
            return "identify loaded origins and bridge/file access before treating JavaScript enablement as risky"
        return "confirm the cited evidence is reachable and security-relevant before treating it as exploitable"

    def _correlated_validation_paths(
        self,
        findings: list[AnalysisFinding],
        evidence_by_id: dict[str, AnalysisEvidence],
    ) -> list[AttackPath]:
        label_to_findings: dict[str, list[AnalysisFinding]] = defaultdict(list)
        for finding in findings:
            if finding.category not in self.ENTRY_POINT_CATEGORIES:
                continue
            for evidence_id in self._evidence_ids(finding):
                evidence = evidence_by_id.get(evidence_id)
                if evidence is not None:
                    label_to_findings[evidence.label].append(finding)

        paths: list[AttackPath] = []
        seen_groups: set[frozenset[str]] = set()
        for label, linked_findings in label_to_findings.items():
            distinct = {finding.title: finding for finding in linked_findings}
            if len(distinct) < 2:
                continue
            group_key = frozenset(distinct.keys())
            if group_key in seen_groups:
                continue
            seen_groups.add(group_key)

            titles = sorted(distinct.keys())
            categories = sorted({finding.category for finding in distinct.values()})
            evidence_ids = sorted({evidence_id for finding in distinct.values() for evidence_id in self._evidence_ids(finding)})
            remediations = list(dict.fromkeys(finding.remediation for finding in distinct.values()))

            paths.append(
                AttackPath(
                    title=f"Correlated validation path via {label}",
                    steps=[
                        f"Shared evidence label: {label}.",
                        f"Findings referencing this evidence: {'; '.join(titles)}.",
                        f"Risk areas involved: {', '.join(categories)}.",
                        (
                            "Why this matters: multiple static findings reference the same evidence item, "
                            "so this should be validated as one connected review target rather than separate isolated notes."
                        ),
                        "Recommended remediation path: " + " AND ".join(remediations),
                    ],
                    evidence_ids=evidence_ids,
                )
            )
        return paths

    @staticmethod
    def _cited_labels(evidence_ids: list[str], evidence_by_id: dict[str, AnalysisEvidence]) -> str:
        labels = [evidence_by_id[evidence_id].label for evidence_id in evidence_ids if evidence_id in evidence_by_id]
        deduped = list(dict.fromkeys(labels))
        return ", ".join(deduped) if deduped else "linked evidence"

    @staticmethod
    def _evidence_ids(finding: AnalysisFinding) -> list[str]:
        parsed = json.loads(finding.evidence_ids_json)
        return [str(item) for item in parsed]

    @staticmethod
    def _severity_counts(findings: list[AnalysisFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @staticmethod
    def _summary(findings: list[AnalysisFinding], severity_counts: dict[str, int]) -> str:
        if not findings:
            return "No evidence-backed findings were generated from the extracted APK evidence."
        counts = ", ".join(f"{severity}: {count}" for severity, count in sorted(severity_counts.items()))
        return f"Generated {len(findings)} static, evidence-backed findings from extracted APK evidence ({counts})."
