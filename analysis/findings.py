from dataclasses import dataclass
from itertools import groupby
import json

from app.db.base import AnalysisEvidence, FindingSeverity


@dataclass(frozen=True)
class FindingCandidate:
    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str
    evidence_ids: list[str]

    @property
    def evidence_ids_json(self) -> str:
        return json.dumps(self.evidence_ids, sort_keys=True)


class EvidenceFindingGenerator:
    def generate(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        findings.extend(self._application_flag_findings(evidence))
        findings.extend(self._coverage_findings(evidence))
        findings.extend(self._manifest_compatibility_findings(evidence))
        findings.extend(self._exported_component_findings(evidence))
        findings.extend(self._provider_review_findings(evidence))
        findings.extend(self._deep_link_findings(evidence))
        findings.extend(self._dangerous_permission_findings(evidence))
        findings.extend(self._code_secret_findings(evidence))
        findings.extend(self._code_risk_findings(evidence))
        return findings

    def _application_flag_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for item in evidence:
            if item.evidence_type != "application_flags":
                continue
            value = self._value(item)
            if value.get("debuggable") == "true":
                findings.append(
                    FindingCandidate(
                        rule_id="android-debuggable-enabled",
                        title="Application is debuggable",
                        severity=FindingSeverity.high,
                        category="Application Configuration",
                        description=self._with_metadata(
                            "The manifest explicitly enables Android debugging for the application.",
                            "High because debuggable release builds can materially aid local inspection, tampering, and runtime instrumentation.",
                            "MASVS-RESILIENCE, MASVS-CODE",
                            "6.8",
                        ),
                        remediation="Disable android:debuggable for release builds and enforce release build signing/configuration gates.",
                        evidence_ids=[item.id],
                    )
                )
            if value.get("allow_backup_effective", value.get("allow_backup")) == "true":
                backup_detail = "The manifest explicitly enables application data backup." if value.get("allow_backup") is not None else "The manifest omits android:allowBackup, so the Android default permits application data backup."
                findings.append(
                    FindingCandidate(
                        rule_id="android-backup-enabled",
                        title="Application backup is enabled",
                        severity=FindingSeverity.medium,
                        category="Application Configuration",
                        description=self._with_metadata(
                            backup_detail,
                            "Medium because risk depends on whether sensitive local data exists; this static check confirms exposure potential, not data sensitivity.",
                            "MASVS-STORAGE",
                            "5.3",
                        ),
                        remediation="Disable android:allowBackup unless backup behavior is required and sensitive data storage has been reviewed.",
                        evidence_ids=[item.id],
                    )
                )
            policy = value.get("network_security_policy") or {}
            effective_cleartext = value.get("uses_cleartext_traffic_effective", value.get("uses_cleartext_traffic"))
            if effective_cleartext == "true":
                cleartext_detail = "The manifest explicitly permits cleartext network traffic." if value.get("uses_cleartext_traffic") is not None else "The manifest omits android:usesCleartextTraffic and the target SDK uses the permissive legacy default."
                findings.append(
                    FindingCandidate(
                        rule_id="android-cleartext-traffic-enabled",
                        title="Cleartext traffic is enabled",
                        severity=FindingSeverity.medium,
                        category="Network Security",
                        description=self._with_metadata(
                            cleartext_detail,
                            "Medium because this enables plaintext transport if code or configuration uses HTTP endpoints; exploitability requires network path or insecure endpoint usage.",
                            "MASVS-NETWORK",
                            "5.9",
                        ),
                        remediation="Disable cleartext traffic and enforce HTTPS through app and network security configuration.",
                        evidence_ids=[item.id],
                    )
                )
            elif policy.get("status") in {"mixed", "unknown"}:
                findings.append(
                    FindingCandidate(
                        rule_id="android-cleartext-policy-uncertain",
                        title="Cleartext traffic policy requires review",
                        severity=FindingSeverity.info,
                        category="Network Security",
                        description=self._with_metadata(
                            "The network security configuration does not establish one global cleartext policy; domain-specific or unavailable configuration may change the effective behavior.",
                            "Informational because static analysis cannot confirm a globally insecure setting from this configuration alone.",
                            "MASVS-NETWORK",
                            "0.0",
                        ),
                        remediation="Review the referenced network security configuration and test each configured domain on the target Android version.",
                        evidence_ids=[item.id],
                    )
                )
        return findings

    def _manifest_compatibility_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        invalid = [item for item in evidence if item.category.value == "component" and self._value(item).get("exported_installation_invalid") is True]
        if not invalid:
            return []
        labels = [str(self._value(item).get("name") or item.label) for item in invalid]
        return [
            FindingCandidate(
                rule_id="android-exported-attribute-required-for-installation",
                title=f"{len(invalid)} component(s) require android:exported for API 31+ installation",
                severity=FindingSeverity.info,
                category="Manifest Compatibility",
                description=self._with_metadata(
                    f"Target SDK 31+ requires an explicit android:exported value for intent-filter components: {', '.join(labels)}. These components are not counted as effectively externally accessible until the manifest is corrected.",
                    "Informational because this is an installation-compatibility issue, not a confirmed exported-component security exposure.",
                    "MASVS-PLATFORM",
                    "0.0",
                ),
                remediation="Declare android:exported explicitly according to the intended component exposure.",
                evidence_ids=[item.id for item in invalid],
            )
        ]

    def _coverage_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        incomplete = []
        for item in evidence:
            if item.evidence_type != "extraction_limits":
                continue
            value = self._value(item)
            limited = False
            for details in value.values():
                if not isinstance(details, dict):
                    continue
                limited = limited or bool(
                    details.get("truncated")
                    or details.get("truncated_rules")
                    or details.get("files_skipped_size")
                    or details.get("unreadable_files")
                )
            if limited:
                incomplete.append(item)
        if not incomplete:
            return []
        return [
            FindingCandidate(
                rule_id="analysis-extraction-coverage-incomplete",
                title="Static extraction coverage was incomplete",
                severity=FindingSeverity.info,
                category="Analysis Coverage",
                description=self._with_metadata(
                    "Some decompiled files or evidence candidates were skipped, unreadable, or limited by configured extraction caps.",
                    "Informational because this is a coverage limitation, not a vulnerability claim; findings may be incomplete until the skipped material is reviewed.",
                    "MASVS-CODE",
                    "0.0",
                ),
                remediation="Review extraction-limits.json and the linked workspace paths; rerun with appropriate limits or inspect skipped files manually.",
                evidence_ids=[item.id for item in incomplete],
            )
        ]

    def _exported_component_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        components = []
        launcher_entries = []
        for item in evidence:
            if item.category.value != "component":
                continue
            value = self._value(item)
            if value.get("launcher_entry") is True:
                launcher_entries.append((str(value.get("component_type") or "component"), item, value))
                continue
            if value.get("exported_effective") is True or value.get("exported") == "true":
                components.append((str(value.get("component_type") or "component"), item, value))

        findings: list[FindingCandidate] = []
        components.sort(key=lambda row: (row[0], bool(row[2].get("permission"))))
        for (component_type, has_permission), grouped in groupby(
            components,
            key=lambda row: (row[0], bool(row[2].get("permission"))),
        ):
            group = list(grouped)
            unprotected = not has_permission
            severity = FindingSeverity.medium if unprotected else FindingSeverity.low
            labels = [str(row[2].get("name") or row[1].label) for row in group]
            qualifier = "without component-level permission protection" if unprotected else "with declared permission protection"
            findings.append(
                FindingCandidate(
                    rule_id=f"android-exported-{component_type}-{'unprotected' if unprotected else 'protected'}",
                    title=f"{len(group)} exported {component_type.replace('_', ' ')} component(s) {qualifier}",
                    severity=severity,
                    category="Exported Components",
                    description=self._with_metadata(
                        f"The manifest exposes these {component_type.replace('_', ' ')} component(s): {', '.join(labels)}.",
                        "Medium when no component permission is declared because other apps may invoke the entry point. Low when a permission is declared because exploitability depends on permission strength and caller access.",
                        "MASVS-PLATFORM",
                        "5.4" if unprotected else "3.7",
                    ),
                    remediation="Review each exported component for intended inter-app access, intent input validation, authorization checks, and sensitive data exposure.",
                    evidence_ids=[row[1].id for row in group],
                )
            )
        if launcher_entries:
            labels = [str(row[2].get("name") or row[1].label) for row in launcher_entries]
            findings.append(
                FindingCandidate(
                    rule_id="android-launcher-entry-points",
                    title=f"{len(launcher_entries)} launcher entry point(s) declared",
                    severity=FindingSeverity.info,
                    category="Exported Components",
                    description=self._with_metadata(
                        f"Launcher entry point(s) are available for normal application startup: {', '.join(labels)}.",
                        "Informational because launcher exposure is expected for an application entry point and is excluded from the unprotected exported-component finding.",
                        "MASVS-PLATFORM",
                        "0.0",
                    ),
                    remediation="Confirm that the launcher entry point performs appropriate authentication and input validation before exposing sensitive functionality.",
                    evidence_ids=[row[1].id for row in launcher_entries],
                )
            )
        return findings

    def _provider_review_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        providers = []
        file_providers = []
        for item in evidence:
            if item.evidence_type != "content_provider":
                continue
            value = self._value(item)
            authorities = str(value.get("authorities") or "")
            name = str(value.get("name") or item.label)
            if "fileprovider" in authorities.lower() or "fileprovider" in name.lower():
                file_providers.append(item)
            elif value.get("exported") == "true":
                providers.append(item)

        findings: list[FindingCandidate] = []
        if providers:
            labels = [item.label for item in providers]
            permission_summary = "; ".join(
                f"{item.label}: read={self._value(item).get('read_permission') or 'none'}, "
                f"write={self._value(item).get('write_permission') or 'none'}"
                for item in providers
            )
            findings.append(
                FindingCandidate(
                    rule_id="android-exported-content-provider-review",
                    title=f"{len(providers)} exported content provider(s) require access-control review",
                    severity=FindingSeverity.medium,
                    category="Exported Components",
                    description=self._with_metadata(
                        f"Exported content provider evidence was found: {', '.join(labels)}. Declared access controls: {permission_summary}.",
                        "Medium because exported providers can expose query/update/delete surfaces; exploitability depends on URI permissions and provider implementation.",
                        "MASVS-PLATFORM, MASVS-STORAGE",
                        "5.8",
                    ),
                    remediation="Review provider permissions, URI grants, path handling, and whether sensitive data can be queried or modified by other apps.",
                    evidence_ids=[item.id for item in providers],
                )
            )
        if file_providers:
            labels = [item.label for item in file_providers]
            findings.append(
                FindingCandidate(
                    rule_id="android-fileprovider-path-review",
                    title=f"{len(file_providers)} FileProvider declaration(s) require path exposure review",
                    severity=FindingSeverity.low,
                    category="File Sharing",
                    description=self._with_metadata(
                        f"FileProvider-like provider evidence was found: {', '.join(labels)}.",
                        "Low as a static manifest finding because FileProvider is commonly legitimate; risk rises if path XML exposes broad roots or caller-controlled file paths.",
                        "MASVS-STORAGE, MASVS-PLATFORM",
                        "3.9",
                    ),
                    remediation="Inspect provider path XML and code paths that build shared URIs; avoid broad roots and validate caller-controlled filenames.",
                    evidence_ids=[item.id for item in file_providers],
                )
            )
        return findings

    def _deep_link_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        deep_links = [item for item in evidence if item.evidence_type == "deep_link"]
        wildcard = []
        normal = []
        for item in deep_links:
            value = self._value(item)
            routes = value.get("routes") or [{"scheme": value.get("scheme"), "host": value.get("host"), "path": value.get("path")}]
            weak_route = any(
                route.get("scheme") in {None, "", "*"}
                or route.get("host") in {None, "", "*"}
                or "*" in str(route.get("host") or "")
                for route in routes
            )
            if value.get("scope") != "explicit_scheme_host" or weak_route:
                wildcard.append(item)
            else:
                normal.append(item)
        findings: list[FindingCandidate] = []
        if wildcard:
            findings.append(
                FindingCandidate(
                    rule_id="android-wildcard-deep-links-declared",
                    title=f"{len(wildcard)} wildcard or weakly scoped deep link(s) declared",
                    severity=FindingSeverity.medium,
                    category="Deep Links",
                    description=self._with_metadata(
                        "The manifest declares deep links with wildcard or missing host/scheme constraints.",
                        "Medium because wildcard deep links can increase app-link hijacking, routing confusion, and unintended component exposure risk.",
                        "MASVS-PLATFORM",
                        "5.4",
                    ),
                    remediation="Use explicit schemes/hosts, Android App Links verification where applicable, and strict input validation in target components.",
                    evidence_ids=[item.id for item in wildcard],
                )
            )
        if normal:
            findings.append(
                FindingCandidate(
                    rule_id="android-deep-links-declared",
                    title=f"{len(normal)} deep link entry point(s) declared",
                    severity=FindingSeverity.low,
                    category="Deep Links",
                    description=self._with_metadata(
                        "The manifest declares deep link routes that can open application components.",
                        "Low because declaration alone is not a vulnerability; exploitability depends on target component validation and authorization.",
                        "MASVS-PLATFORM",
                        "3.5",
                    ),
                    remediation="Validate deep link inputs and authorization checks in each target component.",
                    evidence_ids=[item.id for item in normal],
                )
            )
        return findings

    def _dangerous_permission_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        dangerous = [item for item in evidence if item.evidence_type == "dangerous_permission"]
        if not dangerous:
            return []
        labels = [item.label for item in dangerous]
        return [
            FindingCandidate(
                rule_id="android-dangerous-permissions-requested",
                title=f"{len(dangerous)} dangerous Android permission(s) requested",
                severity=FindingSeverity.info,
                category="Permissions",
                description=self._with_metadata(
                    f"Dangerous permissions requested: {', '.join(labels)}.",
                    "Informational because permission presence alone is not a vulnerability; it guides tester focus and privacy review.",
                    "MASVS-PRIVACY",
                    "0.0",
                ),
                remediation="Confirm each dangerous permission is required, disclosed to users, and protected by runtime permission handling.",
                evidence_ids=[item.id for item in dangerous],
            )
        ]

    def _code_secret_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        secrets = [item for item in evidence if item.category.value == "code_secret"]
        if not secrets:
            return []
        high_confidence = [item for item in secrets if self._value(item).get("confidence") == "high"]

        findings: list[FindingCandidate] = []
        if high_confidence:
            findings.append(
                FindingCandidate(
                    rule_id="android-shape-validated-hardcoded-secrets",
                    title=f"{len(high_confidence)} shape-validated hardcoded secret or key candidate(s)",
                    severity=FindingSeverity.medium,
                    category="Code Review",
                    description=self._with_metadata(
                        "Decompiled source/resources contain values shaped like keys, tokens, passwords, secrets, or Firebase configuration values.",
                        "Medium as a static triage finding because the value shape is plausible for a real secret, but live exploitability and credential validity still require manual validation.",
                        "MASVS-AUTH, MASVS-CRYPTO, MASVS-STORAGE",
                        "5.0",
                    ),
                    remediation="Manually validate each candidate, remove real secrets from client code, rotate exposed credentials, and use server-side secret handling.",
                    evidence_ids=[item.id for item in high_confidence],
                )
            )
        return findings

    def _code_risk_findings(self, evidence: list[AnalysisEvidence]) -> list[FindingCandidate]:
        risks = [
            item
            for item in evidence
            if item.category.value == "code_risk"
            and item.evidence_type not in {"ghidra_analysis", "native_library"}
        ]
        if not risks:
            return []

        grouped: dict[str, list[AnalysisEvidence]] = {}
        for item in risks:
            grouped.setdefault(item.evidence_type, []).append(item)

        findings: list[FindingCandidate] = []
        for evidence_type, items in sorted(grouped.items()):
            title, severity, category, rationale, remediation, masvs, cvss = self._code_risk_metadata(evidence_type, len(items), items)
            findings.append(
                FindingCandidate(
                    rule_id=f"android-code-risk-{evidence_type}",
                    title=title,
                    severity=severity,
                    category=category,
                    description=self._with_metadata(
                        f"{len(items)} code-level evidence record(s) matched this insecure implementation pattern.",
                        rationale,
                        masvs,
                        cvss,
                    ),
                    remediation=self._grounded_remediation(evidence_type, items, remediation),
                    evidence_ids=[item.id for item in items],
                )
            )
        return findings

    @staticmethod
    def _grounded_remediation(evidence_type: str, items: list[AnalysisEvidence], base_remediation: str) -> str:
        if evidence_type == "cleartext_http_endpoint":
            return "Replace the cleartext endpoints with HTTPS-only URLs and confirm that network security configuration blocks plaintext traffic."
        if evidence_type == "trust_all_ssl":
            return "Remove permissive certificate or hostname trust logic and rely on the platform verifier or pinned trust."
        if evidence_type == "weak_crypto_mode":
            return "Use modern authenticated encryption and replace obsolete primitives or modes with approved defaults such as AES-GCM."
        if evidence_type == "insecure_webview_javascript":
            return "Restrict WebView content origins and keep JavaScript enabled only for trusted, tightly scoped flows."
        if evidence_type == "insecure_webview_file_access":
            return "Disable file access unless it is strictly required, and isolate any untrusted WebView content from local files."
        if evidence_type == "webview_javascript_bridge":
            return "Expose only the minimum bridge surface area, validate all bridge traffic, and verify origin restrictions for WebView content."
        if evidence_type == "raw_sql_query_construction":
            return "Use parameterized queries or a vetted ORM path instead of string-concatenated SQL, and verify caller-controlled inputs are not reaching the query."
        return base_remediation.rstrip(".") + "."

    @staticmethod
    def _code_risk_metadata(
        evidence_type: str,
        count: int,
        items: list[AnalysisEvidence] | None = None,
    ) -> tuple[str, FindingSeverity, str, str, str, str, str]:
        if evidence_type == "cleartext_http_endpoint" and items and all(
            json.loads(item.value_json).get("confidence") == "low" for item in items
        ):
            return (
                f"{count} localhost HTTP reference(s) require review",
                FindingSeverity.info,
                "Network Security",
                "Informational because localhost or loopback references commonly represent development configuration and do not establish production cleartext exposure.",
                "Confirm whether the reference is development-only; use HTTPS for any production endpoint.",
                "MASVS-NETWORK",
                "0.0",
            )
        labels = {
            "cleartext_http_endpoint": (
                f"{count} cleartext HTTP endpoint candidate(s) found",
                FindingSeverity.medium,
                "Network Security",
                "Medium because hardcoded HTTP endpoints can expose sensitive traffic if used in production code paths.",
                "Replace cleartext endpoints with HTTPS and verify Network Security Configuration blocks plaintext transport.",
                "MASVS-NETWORK",
                "5.9",
            ),
            "trust_all_ssl": (
                f"{count} TLS trust-management code path(s) require review",
                FindingSeverity.medium,
                "Network Security",
                "Medium because trust-all certificate handling can enable man-in-the-middle attacks if reachable in production.",
                "Remove permissive TrustManager/HostnameVerifier logic and use platform certificate validation or pinned trust where required.",
                "MASVS-NETWORK",
                "6.5",
            ),
            "weak_crypto_mode": (
                f"{count} weak crypto primitive or mode reference(s) found",
                FindingSeverity.medium,
                "Cryptography",
                "Medium because weak algorithms or modes can expose data depending on how they are used.",
                "Use modern authenticated encryption such as AES-GCM and avoid MD5, SHA-1, DES, and ECB mode.",
                "MASVS-CRYPTO",
                "5.6",
            ),
            "insecure_webview_javascript": (
                f"{count} WebView JavaScript enablement point(s) found",
                FindingSeverity.info,
                "WebView",
                "Informational because JavaScript can be legitimate; risk requires untrusted content, weak origin control, or an exposed bridge.",
                "Restrict loaded origins, avoid untrusted content, and pair JavaScript enablement with strict WebView hardening.",
                "MASVS-PLATFORM",
                "3.7",
            ),
            "insecure_webview_file_access": (
                f"{count} WebView file access enablement point(s) found",
                FindingSeverity.medium,
                "WebView",
                "Medium because file access can increase local file exposure risk in unsafe WebView content flows.",
                "Disable file access unless strictly required and isolate WebView content from untrusted inputs.",
                "MASVS-PLATFORM, MASVS-STORAGE",
                "5.0",
            ),
            "webview_javascript_bridge": (
                f"{count} JavaScript bridge exposure point(s) found",
                FindingSeverity.medium,
                "WebView",
                "Medium because JavaScript bridges can expose native methods to web content if origin control is weak.",
                "Expose only minimal bridge methods, restrict loaded content, and validate all bridge inputs.",
                "MASVS-PLATFORM",
                "5.4",
            ),
            "raw_sql_query_construction": (
                f"{count} raw SQL construction candidate(s) found",
                FindingSeverity.medium,
                "Data Storage",
                "Medium because constructed SQL can become injectable if user-controlled data reaches the query.",
                "Use parameterized queries and verify data-flow from user input before confirming exploitability.",
                "MASVS-STORAGE, MASVS-CODE",
                "5.3",
            ),
        }
        return labels.get(
            evidence_type,
            (
                f"{count} code-risk evidence record(s) found",
                FindingSeverity.low,
                "Code Review",
                "Low because this static pattern requires manual code review before confirming risk.",
                "Review linked code evidence and validate whether the pattern is reachable and security-relevant.",
                "MASVS-CODE",
                "3.1",
            ),
        )

    @staticmethod
    def _with_metadata(statement: str, rationale: str, masvs: str, cvss: str) -> str:
        return f"{statement} Severity rationale: {rationale} MASVS/MSTG mapping: {masvs}. Heuristic score (not a calculated CVSS vector): {cvss}."

    @staticmethod
    def _value(item: AnalysisEvidence) -> dict[str, object]:
        return json.loads(item.value_json)
