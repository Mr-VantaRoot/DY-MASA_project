from datetime import datetime
from html import escape
from pathlib import Path
import json

from app.db.base import AnalysisEvidence, AnalysisFinding, AnalysisJob, AnalysisReasoning
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def _display_path(value: object, storage_root: Path | None = None) -> str:
    path = Path(str(value))
    if storage_root is not None:
        try:
            return str(path.resolve().relative_to(storage_root.resolve()))
        except ValueError:
            pass
    parts = path.parts
    if "storage" in parts:
        return "/".join(parts[parts.index("storage") + 1:])
    return path.name or str(value)


def _display_evidence_sources(item: AnalysisEvidence, storage_root: Path | None = None) -> str:
    try:
        payload = json.loads(item.value_json)
    except (TypeError, json.JSONDecodeError):
        payload = {}
    references = payload.get("source_references")
    if isinstance(references, list):
        displayed = []
        for reference in references:
            if not isinstance(reference, dict):
                continue
            displayed.append(
                f"{reference.get('tool', 'source')}: "
                f"{_display_path(reference.get('source_path', ''), storage_root)}"
            )
        if displayed:
            return "; ".join(displayed)
    return _display_path(item.source_path, storage_root)


class HtmlReportGenerator:
    def generate(
        self,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
        findings: list[AnalysisFinding],
        reasoning: list[AnalysisReasoning],
        report_dir: Path,
    ) -> Path:
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{job.id}.html"
        report_path.write_text(
            self._render(job, evidence, findings, reasoning, report_dir),
            encoding="utf-8",
        )
        return report_path

    def _render(
        self,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
        findings: list[AnalysisFinding],
        reasoning: list[AnalysisReasoning],
        report_dir: Path,
    ) -> str:
        evidence_by_id = {item.id: item for item in evidence}
        latest_reasoning = reasoning[-1] if reasoning else None
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>MASA Report - {escape(job.original_filename)}</title>
  <style>
    body {{ color: #172024; font-family: Arial, sans-serif; line-height: 1.55; margin: 40px; }}
    h1, h2, h3 {{ color: #10181b; }}
    h1 {{ font-size: 32px; margin-bottom: 4px; }}
    h2 {{ border-bottom: 1px solid #d7dee1; margin-top: 32px; padding-bottom: 6px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d7dee1; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f5f7f8; }}
    code {{ overflow-wrap: anywhere; }}
    .meta {{ color: #536168; margin-top: 0; }}
    .finding {{ border: 1px solid #d7dee1; margin: 16px 0; padding: 16px; }}
    .callout {{ background: #f5f7f8; border-left: 4px solid #0f766e; margin: 16px 0; padding: 12px 16px; }}
    .severity {{ display: inline-block; font-weight: bold; text-transform: uppercase; }}
    .high {{ color: #b42318; }}
    .medium {{ color: #b45309; }}
    .low {{ color: #0c4a6e; }}
    .info {{ color: #435157; }}
  </style>
</head>
<body>
  <h1>MASA Report</h1>
  <p class="meta">Generated {escape(datetime.utcnow().isoformat())} UTC</p>
  {self._job_summary(job)}
  {self._scope_limitations(evidence)}
  {self._runtime_limitations(evidence)}
  {self._executive_summary(findings, latest_reasoning)}
  {self._key_findings(findings)}
  {self._findings(findings, evidence_by_id, evidence, report_dir)}
  {self._validation_plan(findings, evidence_by_id)}
  {self._runtime_evidence(evidence, report_dir)}
  {self._dynamic_validation_section(evidence, report_dir)}
  {self._evidence(evidence, report_dir)}
  {self._reasoning(latest_reasoning)}
</body>
</html>
"""

    @staticmethod
    def _scope_limitations(evidence: list[AnalysisEvidence]) -> str:
        runtime_count = sum(item.category.value == "runtime" for item in evidence)
        runtime_note = (
            f"<li>DY-MASA recorded {runtime_count} runtime evidence records from an emulator/device run. These records confirm command outcomes and collected artifacts, not exploitability.</li>"
            if runtime_count
            else "<li>No DY-MASA runtime run was included when this report was generated.</li>"
        )
        return """
<h2>Scope and Limitations</h2>
<p>This report is an automated Android security assessment. It is designed to support mobile pentesting, not replace manual validation.</p>
<ul>
  %s
  <li>Manifest findings indicate exposed attack surface, not confirmed exploitability.</li>
  <li>Code/string findings are triage candidates and require manual validation.</li>
  <li>Severity values are evidence-based estimates and should be adjusted after manual review.</li>
</ul>
""" % runtime_note

    @staticmethod
    def _runtime_limitations(evidence: list[AnalysisEvidence]) -> str:
        if not any(item.category.value == "runtime" for item in evidence):
            return """
<h2>Runtime Test Boundaries</h2>
<p>No emulator/device evidence was available. Runtime behavior remains unverified.</p>
"""
        return """
<h2>Runtime Test Boundaries</h2>
<ul>
  <li>Exported activities and deep links are checked for dispatch or reachability only; authorization and input handling still require manual testing.</li>
  <li>Receiver and content-provider invocation is intentionally skipped to avoid modifying application state or accessing data without an explicit test plan.</li>
  <li>Logcat and network indicators are observations, not proof that a vulnerability was exploited.</li>
  <li>No destructive payloads, credential attacks, or uncontrolled external network testing are performed automatically.</li>
  <li>Not checked: network traffic, file contents, how the app handles input, and native code behavior at runtime.</li>
</ul>
"""

    @staticmethod
    def _dynamic_validation_section(evidence: list[AnalysisEvidence], report_dir: Path) -> str:
        validations = [item for item in evidence if item.category.value == "runtime" and item.evidence_type == "dynamic_validation"]
        if not validations:
            return "<h2>Dynamic Validation</h2><p>No per-step DY-MASA validation records were captured.</p>"
        rows = []
        for item in validations:
            try:
                payload = json.loads(item.value_json)
            except json.JSONDecodeError:
                payload = {}
            crashes = payload.get("crash_events") or []
            rows.append(
                f"<tr><td>{escape(str(payload.get('result', 'potential')).upper())}</td>"
                f"<td>{escape(str(payload.get('action', item.label)))}</td>"
                f"<td>{escape(str(len(crashes)))}</td>"
                f"<td><code>{escape(_display_path(payload.get('step_log_path', ''), report_dir.parent))}</code></td></tr>"
            )
        return """
<h2>Dynamic Validation</h2>
<p>Each row is an observed validation step. Results do not assert that a vulnerability was found or exploited.</p>
<table><tr><th>Result</th><th>Step</th><th>Crash events</th><th>Step log</th></tr>%s</table>
<p class="meta"><strong>Not checked:</strong> network traffic, file contents, how the app handles input, and native code behavior at runtime.</p>
""" % "\n".join(rows)

    @staticmethod
    def _job_summary(job: AnalysisJob) -> str:
        return f"""
<h2>Assessment Target</h2>
<table>
  <tr><th>APK filename</th><td>{escape(job.original_filename)}</td></tr>
  <tr><th>SHA-256</th><td><code>{escape(job.sha256 or "Not available")}</code></td></tr>
  <tr><th>File size</th><td>{job.file_size_bytes} bytes</td></tr>
  <tr><th>Job ID</th><td><code>{escape(job.id)}</code></td></tr>
</table>
"""

    @staticmethod
    def _executive_summary(findings: list[AnalysisFinding], reasoning: AnalysisReasoning | None) -> str:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        counts_text = ", ".join(f"{escape(key)}: {value}" for key, value in sorted(counts.items())) or "none"
        summary = reasoning.summary if reasoning else "No reasoning summary was generated."
        return f"""
<h2>Executive Summary</h2>
<p>{escape(summary)}</p>
<p><strong>Finding count:</strong> {len(findings)} ({counts_text})</p>
<div class="callout">Read this report as a triage package: each finding is backed by extracted APK evidence, but exploitability still depends on code review and dynamic validation.</div>
"""

    @staticmethod
    def _key_findings(findings: list[AnalysisFinding]) -> str:
        important = [finding for finding in findings if finding.severity.value in {"high", "medium"}]
        if not important:
            return "<h2>Key Findings</h2><p>No high or medium severity findings were generated.</p>"
        items = "".join(
            f"<li><strong>{escape(finding.severity.value.upper())}</strong> - {escape(finding.title)}</li>"
            for finding in important[:8]
        )
        return f"<h2>Key Findings</h2><ul>{items}</ul>"

    def _findings(
        self,
        findings: list[AnalysisFinding],
        evidence_by_id: dict[str, AnalysisEvidence],
        evidence: list[AnalysisEvidence],
        report_dir: Path,
    ) -> str:
        if not findings:
            return "<h2>Technical Findings</h2><p>No evidence-backed findings were generated.</p>"
        rendered = ["<h2>Technical Findings</h2>"]
        for finding in findings:
            evidence_ids = [str(item) for item in json.loads(finding.evidence_ids_json)]
            rendered.append(
                f"""
<section class="finding">
  <h3>{escape(finding.title)}</h3>
  <p class="severity {escape(finding.severity.value)}">{escape(finding.severity.value)}</p>
  <p><strong>Assessment:</strong> {escape(self._assessment_label(finding))}</p>
  <p><strong>Category:</strong> {escape(finding.category)}</p>
  <p>{escape(finding.description)}</p>
  <p><strong>Remediation:</strong> {escape(finding.remediation)}</p>
  <p><strong>Evidence:</strong></p>
  <ul>{self._evidence_links(evidence_ids, evidence_by_id, report_dir)}</ul>
  {self._runtime_validation_links(finding, evidence)}
</section>
"""
            )
        return "\n".join(rendered)

    @staticmethod
    def _evidence_links(evidence_ids: list[str], evidence_by_id: dict[str, AnalysisEvidence], report_dir: Path) -> str:
        items = []
        for evidence_id in evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            label = evidence.label if evidence else evidence_id
            if evidence is None:
                items.append(f"<li><code>{escape(evidence_id)}</code> - {escape(label)}</li>")
                continue
            try:
                payload = json.loads(evidence.value_json)
            except json.JSONDecodeError:
                payload = {}
            context = str(payload.get("matched_context") or "").strip()
            detail = f"; source: {_display_path(evidence.source_path, report_dir.parent)}"
            if context:
                detail += f"; context: {context}"
            items.append(f"<li><code>{escape(evidence_id)}</code> - {escape(label)}<small>{escape(detail)}</small></li>")
        return "\n".join(items)

    @staticmethod
    def _assessment_label(finding: AnalysisFinding) -> str:
        if finding.severity.value == "info":
            return "Informational observation"
        return "Potential risk from static evidence; exploitability is not confirmed"

    @staticmethod
    def _runtime_validation_links(finding: AnalysisFinding, evidence: list[AnalysisEvidence]) -> str:
        validations = []
        for item in evidence:
            if item.category.value != "runtime" or item.evidence_type != "dynamic_validation":
                continue
            try:
                payload = json.loads(item.value_json)
            except json.JSONDecodeError:
                continue
            if finding.id in [str(value) for value in payload.get("related_finding_ids", [])]:
                validations.append(payload)
        if not validations:
            return "<p class=\"meta\"><strong>Runtime validation:</strong> No directly correlated runtime validation was recorded.</p>"
        rows = "".join(
            f"<tr><td>{escape(str(item.get('result', 'potential')).upper())}</td>"
            f"<td>{escape(str(item.get('action', 'Runtime validation')))}</td>"
            f"<td>{escape(str(item.get('detail', '')))}</td></tr>"
            for item in validations
        )
        return f"""
<p><strong>Runtime validation:</strong> Results below describe observed behavior only; they do not prove exploitability.</p>
<table><tr><th>Result</th><th>Action</th><th>Detail</th></tr>{rows}</table>
"""

    @staticmethod
    def _evidence(evidence: list[AnalysisEvidence], report_dir: Path) -> str:
        rows = []
        for item in evidence[:80]:
            rows.append(
                f"<tr><td>{escape(item.category.value)}</td><td>{escape(item.evidence_type)}</td>"
                f"<td>{escape(item.label)}</td><td><code>{escape(_display_evidence_sources(item, report_dir.parent))}</code></td></tr>"
            )
        body = "\n".join(rows) or '<tr><td colspan="4">No evidence extracted.</td></tr>'
        truncated = (
            f'<p class="meta">Showing first 80 of {len(evidence)} normalized persisted evidence records.</p>'
            if len(evidence) > 80
            else ""
        )
        return f"""
<h2>Evidence Register</h2>
{truncated}
<table>
  <tr><th>Category</th><th>Type</th><th>Label</th><th>Source</th></tr>
  {body}
</table>
"""

    @staticmethod
    def _runtime_evidence(evidence: list[AnalysisEvidence], report_dir: Path) -> str:
        runtime_evidence = [item for item in evidence if item.category.value == "runtime"]
        if not runtime_evidence:
            return ""
        rows = []
        for item in runtime_evidence:
            try:
                payload = json.loads(item.value_json)
            except json.JSONDecodeError:
                payload = {}
            result = payload.get("result", "observed")
            rows.append(
                f"<tr><td>{escape(item.evidence_type)}</td><td>{escape(str(result).upper())}</td>"
                f"<td>{escape(item.label)}</td><td><code>{escape(_display_path(item.source_path, report_dir.parent))}</code></td></tr>"
            )
        rows = "\n".join(rows)
        limits_note = ""
        limit_items = [item for item in runtime_evidence if item.evidence_type == "extraction_limits"]
        if limit_items:
            details = []
            for item in limit_items:
                try:
                    payload = json.loads(item.value_json)
                except json.JSONDecodeError:
                    payload = {}
                for name, values in payload.items():
                    if not isinstance(values, dict):
                        continue
                    noteworthy = {key: value for key, value in values.items() if key not in {"max_file_bytes", "max_evidence_per_rule"} and value not in (0, False, [], {})}
                    if noteworthy:
                        details.append(f"{name}: {json.dumps(noteworthy, sort_keys=True)}")
                normalization = payload.get("normalization")
                if isinstance(normalization, dict):
                    details.append(
                        "evidence normalization: "
                        f"{normalization.get('raw_count', 0)} raw records -> "
                        f"{normalization.get('normalized_count', 0)} persisted records; "
                        f"{normalization.get('cross_tool_duplicates_removed', 0)} cross-tool and "
                        f"{normalization.get('same_tool_duplicates_removed', 0)} same-tool duplicates removed"
                    )
            limits_note = "<p><strong>Extraction coverage:</strong> reported for transparency; " + escape("; ".join(details) or "no limits reached") + ".</p>"
        return f"""
<h2>DY-MASA Runtime Evidence</h2>
<p>Captured during emulator/device execution. This section records observed runtime activity and artifacts; it does not assert vulnerability exploitability.</p>
{limits_note}
<table>
  <tr><th>Type</th><th>Result</th><th>Observation</th><th>Artifact / Source</th></tr>
  {rows}
</table>
"""

    @staticmethod
    def _validation_plan(findings: list[AnalysisFinding], evidence_by_id: dict[str, AnalysisEvidence]) -> str:
        if not findings:
            return ""
        items = []
        for finding in findings[:8]:
            cited = [evidence_by_id[evidence_id].label for evidence_id in json.loads(finding.evidence_ids_json) if evidence_id in evidence_by_id]
            if finding.category == "Exported Components":
                action = "Open the decompiled component and verify intent input validation, authorization, and sensitive data handling."
            elif finding.category == "Deep Links":
                action = "Exercise the deep link route with controlled inputs and verify routing, authorization, and app-link verification behavior."
            elif finding.category == "Code Review":
                action = "Validate whether each candidate value is active, rotate exposed credentials if confirmed, and move secrets server-side."
            elif finding.category == "Network Security":
                action = "Search for HTTP endpoints and test whether sensitive traffic can occur over cleartext transport."
            else:
                action = "Review the linked evidence manually and confirm exploitability before treating it as a confirmed vulnerability."
            items.append(f"<li><strong>{escape(finding.title)}:</strong> inspect {escape(', '.join(cited[:3]) or 'the linked evidence')}; {escape(action)}</li>")
        return f"<h2>Manual Validation Plan</h2><ol>{''.join(items)}</ol>"

    @staticmethod
    def _reasoning(reasoning: AnalysisReasoning | None) -> str:
        if reasoning is None:
            return "<h2>Structured Reasoning</h2><p>No reasoning generated.</p>"
        attack_paths = json.loads(reasoning.attack_paths_json)
        rendered_paths = []
        for path in attack_paths:
            steps = "".join(f"<li>{escape(str(step))}</li>" for step in path.get("steps", []))
            rendered_paths.append(f"<h3>{escape(str(path.get('title', 'Attack path')))}</h3><ol>{steps}</ol>")
        return f"""
<h2>Structured Risk Summary</h2>
<p><strong>Provider:</strong> {escape(reasoning.provider)}</p>
<p>{escape(reasoning.limitations)}</p>
{''.join(rendered_paths)}
"""


class PdfReportGenerator:
    @staticmethod
    def _safe_text(value: object) -> str:
        """Render APK/database text literally instead of as ReportLab markup."""
        return escape(str(value), quote=True)

    def generate(
        self,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
        findings: list[AnalysisFinding],
        reasoning: list[AnalysisReasoning],
        report_dir: Path,
    ) -> Path:
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{job.id}.pdf"
        document = SimpleDocTemplate(
            str(report_path),
            pagesize=LETTER,
            rightMargin=0.7 * inch,
            leftMargin=0.7 * inch,
            topMargin=0.7 * inch,
            bottomMargin=0.7 * inch,
            title=f"MASA Report - {job.original_filename}",
        )
        document.build(self._story(job, evidence, findings, reasoning, report_dir))
        return report_path

    def _story(
        self,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
        findings: list[AnalysisFinding],
        reasoning: list[AnalysisReasoning],
        report_dir: Path,
    ) -> list[object]:
        styles = getSampleStyleSheet()
        title = styles["Title"]
        heading = styles["Heading2"]
        body = styles["BodyText"]
        code = ParagraphStyle(
            "Code",
            parent=body,
            fontName="Courier",
            fontSize=8,
            leading=10,
            wordWrap="CJK",
        )

        latest_reasoning = reasoning[-1] if reasoning else None
        runtime_scope = (
            "DY-MASA runtime testing was performed; runtime records distinguish observed behavior from potential risk and do not by themselves prove exploitability."
            if any(item.category.value == "runtime" for item in evidence)
            else "No DY-MASA runtime testing was performed for this report."
        )
        story: list[object] = [
            Paragraph("MASA Report", title),
            Paragraph(self._safe_text(f"Generated {datetime.utcnow().isoformat()} UTC"), body),
            Spacer(1, 0.2 * inch),
            Paragraph("Assessment Target", heading),
            self._table(
                [
                    ["APK filename", job.original_filename],
                    ["SHA-256", job.sha256 or "Not available"],
                    ["File size", f"{job.file_size_bytes} bytes"],
                    ["Job ID", job.id],
                ]
            ),
            Spacer(1, 0.2 * inch),
            Paragraph("Scope and Limitations", heading),
            Paragraph(
                self._safe_text(
                    "This is an automated assessment of APK-derived evidence, not a complete manual mobile penetration test. "
                    + runtime_scope + " Manifest findings indicate exposed attack surface, and code/string findings require manual validation."
                ),
                body,
            ),
            Spacer(1, 0.2 * inch),
            Paragraph("Runtime Test Boundaries", heading),
            *self._runtime_limitations_story(evidence, body),
            Spacer(1, 0.2 * inch),
            Paragraph("Executive Summary", heading),
            Paragraph(self._safe_text(self._executive_summary_text(findings, latest_reasoning)), body),
            Spacer(1, 0.2 * inch),
            Paragraph("Key Findings", heading),
            *self._key_findings_story(findings, body),
            Spacer(1, 0.2 * inch),
            Paragraph("Technical Findings", heading),
        ]

        evidence_by_id = {item.id: item for item in evidence}
        if findings:
            for finding in findings:
                story.extend(self._finding_story(finding, evidence_by_id, styles, code, report_dir))
        else:
            story.append(Paragraph("No evidence-backed findings were generated.", body))

        story.extend(
            [
                Spacer(1, 0.2 * inch),
                Paragraph("Evidence Register", heading),
                Paragraph(
                    self._safe_text(
                        f"Showing first {min(80, len(evidence))} of {len(evidence)} normalized persisted evidence records."
                    ),
                    body,
                ),
                self._evidence_table(evidence, report_dir),
                *self._runtime_evidence_story(evidence, heading, body, report_dir),
                *self._dynamic_validation_story(evidence, heading, body, report_dir),
                Spacer(1, 0.2 * inch),
                Paragraph("Manual Validation Plan", heading),
                *self._validation_plan_story(findings, body, evidence_by_id),
                Spacer(1, 0.2 * inch),
                Paragraph("Structured Risk Summary", heading),
            ]
        )
        story.extend(self._reasoning_story(latest_reasoning, body))
        return story

    @staticmethod
    def _executive_summary_text(findings: list[AnalysisFinding], reasoning: AnalysisReasoning | None) -> str:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        counts_text = ", ".join(f"{key}: {value}" for key, value in sorted(counts.items())) or "none"
        summary = reasoning.summary if reasoning else "No reasoning summary was generated."
        return f"{summary} Finding count: {len(findings)} ({counts_text})."

    @staticmethod
    def _key_findings_story(findings: list[AnalysisFinding], body: ParagraphStyle) -> list[object]:
        important = [finding for finding in findings if finding.severity.value in {"high", "medium"}]
        if not important:
            return [Paragraph("No high or medium severity findings were generated.", body)]
        return [
            Paragraph(PdfReportGenerator._safe_text(f"{finding.severity.value.upper()} - {finding.title}"), body)
            for finding in important[:8]
        ]

    @staticmethod
    def _validation_plan_story(findings: list[AnalysisFinding], body: ParagraphStyle, evidence_by_id: dict[str, AnalysisEvidence]) -> list[object]:
        if not findings:
            return [Paragraph("No validation actions were generated.", body)]
        actions = []
        for finding in findings[:8]:
            cited = [evidence_by_id[evidence_id].label for evidence_id in json.loads(finding.evidence_ids_json) if evidence_id in evidence_by_id]
            if finding.category == "Exported Components":
                action = "Review decompiled component input handling, authorization, and sensitive data access."
            elif finding.category == "Deep Links":
                action = "Exercise the route with controlled inputs and verify routing, authorization, and app-link verification."
            elif finding.category == "Code Review":
                action = "Validate candidate values, rotate confirmed exposed credentials, and move secrets server-side."
            elif finding.category == "Network Security":
                action = "Search for HTTP endpoints and test whether sensitive traffic can use cleartext transport."
            else:
                action = "Review linked evidence manually and confirm exploitability before treating it as confirmed."
            actions.append(Paragraph(PdfReportGenerator._safe_text(f"{finding.title}: inspect {', '.join(cited[:3]) or 'linked evidence'}; {action}"), body))
        return actions

    def _finding_story(
        self,
        finding: AnalysisFinding,
        evidence_by_id: dict[str, AnalysisEvidence],
        styles: dict[str, ParagraphStyle],
        code: ParagraphStyle,
        report_dir: Path,
    ) -> list[object]:
        evidence_ids = [str(item) for item in json.loads(finding.evidence_ids_json)]
        evidence_lines = []
        for evidence_id in evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            label = evidence.label if evidence else evidence_id
            if evidence is None:
                evidence_lines.append(f"{evidence_id} - {label}")
                continue
            try:
                payload = json.loads(evidence.value_json)
            except json.JSONDecodeError:
                payload = {}
            context = str(payload.get("matched_context") or "").strip()
            source = _display_path(evidence.source_path, report_dir.parent)
            evidence_lines.append(f"{evidence_id} - {label} [source: {source}]" + (f" [context: {context}]" if context else ""))
        story = [
            Paragraph(self._safe_text(finding.title), styles["Heading3"]),
            Paragraph(self._safe_text(f"Severity: {finding.severity.value.upper()} | Category: {finding.category}"), styles["BodyText"]),
            Paragraph(self._safe_text(f"Assessment: {HtmlReportGenerator._assessment_label(finding)}"), styles["BodyText"]),
            Paragraph(self._safe_text(finding.description), styles["BodyText"]),
            Paragraph(self._safe_text(f"Remediation: {finding.remediation}"), styles["BodyText"]),
            Paragraph(self._safe_text("Evidence: " + "; ".join(evidence_lines)), code),
            Spacer(1, 0.12 * inch),
        ]
        validations = []
        for item in evidence_by_id.values():
            if item.category.value != "runtime" or item.evidence_type != "dynamic_validation":
                continue
            try:
                payload = json.loads(item.value_json)
            except json.JSONDecodeError:
                continue
            if finding.id in [str(value) for value in payload.get("related_finding_ids", [])]:
                validations.append(payload)
        if validations:
            story.append(Paragraph("Runtime Validation (observed behavior; not exploitability proof)", styles["Heading4"]))
            for validation in validations:
                story.append(
                    Paragraph(
                        PdfReportGenerator._safe_text(
                            f"{str(validation.get('result', 'potential')).upper()} - "
                            f"{validation.get('action', 'Runtime validation')}: {validation.get('detail', '')}"
                        ),
                        styles["BodyText"],
                    )
                )
        else:
            story.append(Paragraph("Runtime validation: No directly correlated runtime validation was recorded.", styles["BodyText"]))
        return story

    @staticmethod
    def _reasoning_story(reasoning: AnalysisReasoning | None, body: ParagraphStyle) -> list[object]:
        if reasoning is None:
            return [Paragraph("No reasoning generated.", body)]
        story: list[object] = [
            Paragraph(PdfReportGenerator._safe_text(f"Provider: {reasoning.provider}"), body),
            Paragraph(PdfReportGenerator._safe_text(reasoning.limitations), body),
        ]
        for attack_path in json.loads(reasoning.attack_paths_json):
            steps = " ".join(str(step) for step in attack_path.get("steps", []))
            story.append(Paragraph(PdfReportGenerator._safe_text(f"{attack_path.get('title', 'Attack path')}: {steps}"), body))
        return story

    def _runtime_evidence_story(
        self,
        evidence: list[AnalysisEvidence],
        heading: ParagraphStyle,
        body: ParagraphStyle,
        report_dir: Path,
    ) -> list[object]:
        runtime_evidence = [item for item in evidence if item.category.value == "runtime"]
        if not runtime_evidence:
            return []
        rows = [["Type", "Result", "Observation", "Artifact / Source"]]
        for item in runtime_evidence:
            try:
                payload = json.loads(item.value_json)
            except json.JSONDecodeError:
                payload = {}
            rows.append([item.evidence_type, str(payload.get("result", "observed")).upper(), item.label, _display_path(item.source_path, report_dir.parent)])
        limits_note = []
        limit_items = [item for item in runtime_evidence if item.evidence_type == "extraction_limits"]
        if limit_items:
            details = []
            for item in limit_items:
                try:
                    payload = json.loads(item.value_json)
                except json.JSONDecodeError:
                    payload = {}
                for name, values in payload.items():
                    if isinstance(values, dict):
                        noteworthy = {key: value for key, value in values.items() if key not in {"max_file_bytes", "max_evidence_per_rule"} and value not in (0, False, [], {})}
                        if noteworthy:
                            details.append(f"{name}: {json.dumps(noteworthy, sort_keys=True)}")
                normalization = payload.get("normalization")
                if isinstance(normalization, dict):
                    details.append(
                        "evidence normalization: "
                        f"{normalization.get('raw_count', 0)} raw records -> "
                        f"{normalization.get('normalized_count', 0)} persisted records; "
                        f"{normalization.get('cross_tool_duplicates_removed', 0)} cross-tool and "
                        f"{normalization.get('same_tool_duplicates_removed', 0)} same-tool duplicates removed"
                    )
            limits_note = [Paragraph(PdfReportGenerator._safe_text("Extraction coverage: " + ("; ".join(details) if details else "no limits reached") + "."), body)]
        return [
            Spacer(1, 0.2 * inch),
            Paragraph("DY-MASA Runtime Evidence", heading),
            Paragraph(
                "Captured during emulator/device execution. These records document observed runtime activity and artifacts; they do not assert vulnerability exploitability.",
                body,
            ),
            *limits_note,
            self._table(rows),
        ]

    @staticmethod
    def _dynamic_validation_story(
        evidence: list[AnalysisEvidence],
        heading: ParagraphStyle,
        body: ParagraphStyle,
        report_dir: Path,
    ) -> list[object]:
        validations = [item for item in evidence if item.category.value == "runtime" and item.evidence_type == "dynamic_validation"]
        if not validations:
            return [Paragraph("Dynamic Validation: no per-step records were captured.", body)]
        story: list[object] = [
            Spacer(1, 0.2 * inch),
            Paragraph("Dynamic Validation", heading),
            Paragraph("These are observed validation steps, not claims that a vulnerability was found or exploited.", body),
        ]
        for item in validations:
            try:
                payload = json.loads(item.value_json)
            except json.JSONDecodeError:
                payload = {}
            story.append(Paragraph(
                PdfReportGenerator._safe_text(
                    f"{str(payload.get('result', 'potential')).upper()} - {payload.get('action', item.label)}; "
                    f"crashes: {len(payload.get('crash_events') or [])}; log: {_display_path(payload.get('step_log_path', 'not recorded'), report_dir.parent)}"
                ),
                body,
            ))
        story.append(Paragraph("Not checked: network traffic, file contents, how the app handles input, and native code behavior at runtime.", body))
        return story

    @staticmethod
    def _runtime_limitations_story(evidence: list[AnalysisEvidence], body: ParagraphStyle) -> list[object]:
        if not any(item.category.value == "runtime" for item in evidence):
            return [Paragraph("No emulator/device evidence was available; runtime behavior remains unverified.", body)]
        return [
            Paragraph("Exported activities and deep links are checked for dispatch or reachability only; authorization and input handling require manual testing.", body),
            Paragraph("Receiver and content-provider invocation is intentionally skipped to avoid modifying application state or accessing data without an explicit test plan.", body),
            Paragraph("Logcat and network indicators are observations, not proof that a vulnerability was exploited.", body),
            Paragraph("No destructive payloads, credential attacks, or uncontrolled external network testing are performed automatically.", body),
            Paragraph("Not checked: network traffic, file contents, how the app handles input, and native code behavior at runtime.", body),
        ]

    def _evidence_table(self, evidence: list[AnalysisEvidence], report_dir: Path) -> Table:
        rows = [["Category", "Type", "Label", "Source"]]
        rows.extend(
            [item.category.value, item.evidence_type, item.label, _display_evidence_sources(item, report_dir.parent)]
            for item in evidence[:80]
        )
        if len(rows) == 1:
            rows.append(["-", "-", "No evidence extracted", "-"])
        table_rows = []
        table_style = ParagraphStyle("EvidenceTable", parent=getSampleStyleSheet()["BodyText"], fontSize=7, leading=8)
        for row in rows:
            table_rows.append([Paragraph(self._safe_text(str(cell)), table_style) for cell in row])
        table = self._table(table_rows)
        table._argW = [0.85 * inch, 1.05 * inch, 2.35 * inch, 2.85 * inch]
        return table

    @staticmethod
    def _table(rows: list[list[str]]) -> Table:
        table = Table(rows, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f7f8")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d7dee1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("LEADING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        return table
