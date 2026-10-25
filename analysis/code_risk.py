from dataclasses import dataclass
from pathlib import Path
import json
import re

from app.db.base import EvidenceCategory
from analysis.evidence import EvidenceItem


@dataclass(frozen=True)
class CodeRiskRule:
    evidence_type: str
    label: str
    pattern: re.Pattern[str]
    confidence: str
    description: str


class CodeRiskEvidenceExtractor:
    NON_NETWORK_HTTP_HOSTS = (
        "http://schemas.android.com/",
        "http://www.w3.org/",
        "http://ns.adobe.com/",
    )
    COMMON_LIBRARY_PATH_FRAGMENTS = (
        "com/google/crypto/tink/",
        "com/google/android/gms/",
        "androidx/",
        "android/support/",
        "kotlin/",
        "okhttp3/",
        "retrofit2/",
        "build/generated/",
        "build/intermediates/",
        "app/build/",
    )
    RULES = (
        CodeRiskRule(
            evidence_type="insecure_webview_javascript",
            label="WebView JavaScript enabled",
            pattern=re.compile(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)", re.IGNORECASE),
            confidence="medium",
            description="JavaScript is enabled in a WebView. Risk depends on loaded content and JavaScript bridge exposure.",
        ),
        CodeRiskRule(
            evidence_type="insecure_webview_file_access",
            label="WebView file access enabled",
            pattern=re.compile(r"\.setAllowFileAccess\s*\(\s*true\s*\)", re.IGNORECASE),
            confidence="medium",
            description="WebView file access is enabled. This can increase local file exposure risk in unsafe WebView flows.",
        ),
        CodeRiskRule(
            evidence_type="webview_javascript_bridge",
            label="JavaScript bridge exposed",
            pattern=re.compile(r"\.addJavascriptInterface\s*\(", re.IGNORECASE),
            confidence="medium",
            description="A JavaScript bridge is exposed to WebView content and requires strict origin/content control.",
        ),
        CodeRiskRule(
            evidence_type="trust_all_ssl",
            label="Trust-all TLS implementation",
            pattern=re.compile(
                r"(?:\bTrustAll\w*\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b|"
                r"checkServerTrusted\s*\([^)]*\)\s*\{\s*(?:return\s*;|return\s+(?:true|null)\s*;?)?\s*\}|"
                r"\bHostnameVerifier\b[\s\S]{0,500}?verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\})",
                re.IGNORECASE,
            ),
            confidence="medium",
            description="A permissive TLS trust or hostname-verification implementation was found; verify reachability and production use.",
        ),
        CodeRiskRule(
            evidence_type="weak_crypto_mode",
            label="Weak cryptographic primitive or mode",
            pattern=re.compile(
                r"(Cipher\.getInstance\s*\(\s*[\"'][^\"']*(?:AES/ECB|DES/|DESede)[^\"']*[\"']"
                r"|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA1|SHA-1)[\"']"
                r"|const-string\s+\w+,\s*[\"'](?:AES/ECB[^\"']*|DES/[^\"']*|DESede|MD5)[\"'])",
                re.IGNORECASE,
            ),
            confidence="medium",
            description="A weak cryptographic primitive or mode appears in code or configuration.",
        ),
        CodeRiskRule(
            evidence_type="cleartext_http_endpoint",
            label="Cleartext HTTP endpoint",
            pattern=re.compile(r"http://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s\"'<>)]*)?", re.IGNORECASE),
            confidence="high",
            description="A cleartext HTTP endpoint was found in decompiled code/resources.",
        ),
        CodeRiskRule(
            evidence_type="raw_sql_query_construction",
            label="Raw SQL query construction",
            pattern=re.compile(r"(rawQuery|execSQL)\s*\([^;\n]*(\+|String\.format|append)", re.IGNORECASE),
            confidence="medium",
            description="Raw SQL execution appears to use string construction. Review whether user-controlled data can reach the query.",
        ),
    )
    EXTENSIONS = {".java", ".kt", ".xml", ".json", ".properties", ".gradle", ".smali"}
    MAX_FILE_BYTES = 1024 * 1024
    MAX_EVIDENCE_PER_RULE = 12

    def __init__(self) -> None:
        self.limit_metadata = {
            "max_evidence_per_rule": self.MAX_EVIDENCE_PER_RULE,
            "emitted_by_rule": {},
            "truncated_rules": [],
            "files_seen": 0,
            "files_scanned": 0,
            "files_skipped_size": 0,
            "unreadable_files": 0,
            "unreadable_file_samples": [],
        }

    def extract(self, *roots: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        seen_per_rule: dict[str, int] = {}
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                self.limit_metadata["files_seen"] += 1
                try:
                    is_candidate = path.is_file() and path.suffix.lower() in self.EXTENSIONS
                    size = path.stat().st_size if is_candidate else 0
                except OSError:
                    self._record_unreadable(path)
                    continue
                if not is_candidate:
                    continue
                if size > self.MAX_FILE_BYTES:
                    self.limit_metadata["files_skipped_size"] += 1
                    continue
                self.limit_metadata["files_scanned"] += 1
                evidence.extend(self._scan_file(path, seen_per_rule))
        self.limit_metadata["emitted_by_rule"] = dict(seen_per_rule)
        return evidence

    def _scan_file(self, path: Path, seen_per_rule: dict[str, int]) -> list[EvidenceItem]:
        results: list[EvidenceItem] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            self._record_unreadable(path)
            return results

        file_text = "\n".join(lines)
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for rule in self.RULES:
                material = stripped
                if rule.evidence_type == "trust_all_ssl":
                    material = (
                        file_text
                        if "HostnameVerifier" in file_text and "verify" in stripped
                        else (
                            " ".join(lines[line_number - 1 : line_number + 4])
                            if any(token in stripped for token in ("checkServerTrusted", "TrustAll", "ALLOW_ALL_HOSTNAME_VERIFIER"))
                            else stripped
                        )
                    )
                match = rule.pattern.search(material)
                if not match:
                    continue
                if self._should_ignore_match(path, rule, match.group(0)):
                    continue
                if seen_per_rule.get(rule.evidence_type, 0) >= self.MAX_EVIDENCE_PER_RULE:
                    truncated_rules = self.limit_metadata["truncated_rules"]
                    if rule.evidence_type not in truncated_rules:
                        truncated_rules.append(rule.evidence_type)
                    continue
                seen_per_rule[rule.evidence_type] = seen_per_rule.get(rule.evidence_type, 0) + 1
                ownership = self._ownership(path)
                local_endpoint = rule.evidence_type == "cleartext_http_endpoint" and bool(
                    re.search(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/|$)", match.group(0), re.IGNORECASE)
                )
                confidence = "low" if local_endpoint else rule.confidence
                description = (
                    "A localhost or loopback HTTP reference was found; this is commonly a development/configuration value and is not evidence of production cleartext traffic."
                    if local_endpoint
                    else rule.description
                )
                results.append(
                    EvidenceItem(
                        category=EvidenceCategory.code_risk,
                        evidence_type=rule.evidence_type,
                        label=f"{rule.label} in {path.name}:{line_number}",
                        value={
                            "file": str(path),
                            "line": line_number,
                            "matched_context": self._redact(stripped),
                            "matched_value": self._redact(match.group(0)),
                            "confidence": confidence,
                            "description": description,
                            "ownership": ownership,
                        },
                        source_path=path,
                        source_node=f"line:{line_number}",
                    )
                )
        return results

    @classmethod
    def _ownership(cls, path: Path) -> str:
        normalized = path.as_posix().lower()
        if any(fragment in normalized for fragment in cls.COMMON_LIBRARY_PATH_FRAGMENTS):
            return "third_party_library"
        if "/b3nac/injuredandroid/" in normalized or "b3nac.injuredandroid" in normalized:
            return "first_party_application"
        return "unknown"

    def _record_unreadable(self, path: Path) -> None:
        self.limit_metadata["unreadable_files"] += 1
        samples = self.limit_metadata["unreadable_file_samples"]
        if len(samples) < 10:
            samples.append(str(path))

    def _should_ignore_match(self, path: Path, rule: CodeRiskRule, matched_value: str) -> bool:
        normalized_path = path.as_posix().lower()
        if any(fragment in normalized_path for fragment in self.COMMON_LIBRARY_PATH_FRAGMENTS):
            return True
        if rule.evidence_type == "cleartext_http_endpoint":
            lowered = matched_value.lower()
            if any(lowered.startswith(host) for host in self.NON_NETWORK_HTTP_HOSTS):
                return True
        return False

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 160:
            return value
        return value[:157] + "..."
