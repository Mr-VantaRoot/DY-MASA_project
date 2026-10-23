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
                r"checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}?|X509TrustManager|TrustAll|ALLOW_ALL_HOSTNAME_VERIFIER",
                re.IGNORECASE,
            ),
            confidence="medium",
            description="TLS trust-management code was found and should be reviewed for trust-all certificate validation.",
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

    def extract(self, *roots: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        seen_per_rule: dict[str, int] = {}
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in self.EXTENSIONS:
                    continue
                if path.stat().st_size > self.MAX_FILE_BYTES:
                    continue
                evidence.extend(self._scan_file(path, seen_per_rule))
        return evidence

    def _scan_file(self, path: Path, seen_per_rule: dict[str, int]) -> list[EvidenceItem]:
        results: list[EvidenceItem] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return results

        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for rule in self.RULES:
                if seen_per_rule.get(rule.evidence_type, 0) >= self.MAX_EVIDENCE_PER_RULE:
                    continue
                match = rule.pattern.search(stripped)
                if not match:
                    continue
                if self._should_ignore_match(path, rule, match.group(0)):
                    continue
                seen_per_rule[rule.evidence_type] = seen_per_rule.get(rule.evidence_type, 0) + 1
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
                            "confidence": rule.confidence,
                            "description": rule.description,
                        },
                        source_path=path,
                        source_node=f"line:{line_number}",
                    )
                )
        return results

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
