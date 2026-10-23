from dataclasses import dataclass
from bisect import bisect_right
from pathlib import Path
import json
import math
import re
import xml.etree.ElementTree as ET

from app.db.base import EvidenceCategory


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}


@dataclass(frozen=True)
class EvidenceItem:
    category: EvidenceCategory
    evidence_type: str
    label: str
    value: dict[str, object]
    source_path: Path
    source_node: str | None = None

    @property
    def value_json(self) -> str:
        return json.dumps(self.value, sort_keys=True)


class ManifestEvidenceExtractor:
    COMPONENT_TAGS = {
        "activity": "activity",
        "activity-alias": "activity_alias",
        "service": "service",
        "receiver": "broadcast_receiver",
        "provider": "content_provider",
    }

    def extract(self, apktool_output_path: Path) -> list[EvidenceItem]:
        manifest_path = apktool_output_path / "AndroidManifest.xml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Decoded manifest not found: {manifest_path}")

        tree = ET.parse(manifest_path)
        root = tree.getroot()
        evidence: list[EvidenceItem] = []

        package_name = root.attrib.get("package")
        evidence.append(
            EvidenceItem(
                category=EvidenceCategory.manifest,
                evidence_type="manifest_metadata",
                label="AndroidManifest metadata",
                value={
                    "package": package_name,
                    "version_code": self._android_attr(root, "versionCode"),
                    "version_name": self._android_attr(root, "versionName"),
                    "min_sdk": self._uses_sdk_value(root, "minSdkVersion"),
                    "target_sdk": self._uses_sdk_value(root, "targetSdkVersion"),
                },
                source_path=manifest_path,
                source_node="manifest",
            )
        )

        evidence.extend(self._permissions(root, manifest_path))

        application = root.find("application")
        if application is not None:
            evidence.extend(self._application_flags(application, manifest_path))
            evidence.extend(self._components(application, manifest_path))

        return evidence

    def _permissions(self, root: ET.Element, manifest_path: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for permission in root.findall("uses-permission"):
            name = self._android_attr(permission, "name")
            if not name:
                continue
            is_dangerous = name in DANGEROUS_PERMISSIONS
            evidence.append(
                EvidenceItem(
                    category=EvidenceCategory.permission,
                    evidence_type="dangerous_permission" if is_dangerous else "permission",
                    label=name,
                    value={"name": name, "dangerous": is_dangerous},
                    source_path=manifest_path,
                    source_node="uses-permission",
                )
            )
        return evidence

    def _application_flags(self, application: ET.Element, manifest_path: Path) -> list[EvidenceItem]:
        flags = {
            "debuggable": self._android_attr(application, "debuggable"),
            "allow_backup": self._android_attr(application, "allowBackup"),
            "uses_cleartext_traffic": self._android_attr(application, "usesCleartextTraffic"),
            "network_security_config": self._android_attr(application, "networkSecurityConfig"),
        }
        return [
            EvidenceItem(
                category=EvidenceCategory.application_flag,
                evidence_type="application_flags",
                label="Application security flags",
                value=flags,
                source_path=manifest_path,
                source_node="application",
            )
        ]

    def _components(self, application: ET.Element, manifest_path: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for tag, component_type in self.COMPONENT_TAGS.items():
            for component in application.findall(tag):
                name = self._android_attr(component, "name")
                exported = self._android_attr(component, "exported")
                intent_filters = component.findall("intent-filter")
                evidence.append(
                    EvidenceItem(
                        category=EvidenceCategory.component,
                        evidence_type=component_type,
                        label=name or f"Unnamed {component_type}",
                        value={
                            "name": name,
                            "component_type": component_type,
                            "exported": exported,
                            "intent_filter_count": len(intent_filters),
                            "permission": self._android_attr(component, "permission"),
                            "authorities": self._android_attr(component, "authorities"),
                        },
                        source_path=manifest_path,
                        source_node=tag,
                    )
                )
                evidence.extend(self._deep_links(name, component_type, intent_filters, manifest_path))
        return evidence

    def _deep_links(
        self,
        component_name: str | None,
        component_type: str,
        intent_filters: list[ET.Element],
        manifest_path: Path,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for intent_filter in intent_filters:
            for data in intent_filter.findall("data"):
                scheme = self._android_attr(data, "scheme")
                host = self._android_attr(data, "host")
                path = self._android_attr(data, "path") or self._android_attr(data, "pathPrefix")
                if not any([scheme, host, path]):
                    continue
                evidence.append(
                    EvidenceItem(
                        category=EvidenceCategory.deep_link,
                        evidence_type="deep_link",
                        label=f"{scheme or '*'}://{host or '*'}{path or ''}",
                        value={
                            "component_name": component_name,
                            "component_type": component_type,
                            "scheme": scheme,
                            "host": host,
                            "path": path,
                            "mime_type": self._android_attr(data, "mimeType"),
                        },
                        source_path=manifest_path,
                        source_node="intent-filter/data",
                    )
                )
        return evidence

    @staticmethod
    def _android_attr(element: ET.Element, name: str) -> str | None:
        return element.attrib.get(f"{ANDROID_NS}{name}")

    def _uses_sdk_value(self, root: ET.Element, name: str) -> str | None:
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is None:
            return None
        return self._android_attr(uses_sdk, name)


class CodeSecretEvidenceExtractor:
    SECRET_KEYWORDS = {
        "possible_api_key": ("api_key", "apikey", "api-key", "x-api-key"),
        "possible_secret": ("secret", "client_secret", "app_secret"),
        "possible_token": ("token", "auth_token", "access_token", "bearer"),
        "possible_password": ("password", "passwd", "pwd"),
        "possible_firebase": ("firebase", "google_api_key", "mobilesdk_app_id"),
    }
    EXCLUDED_RESOURCE_FILENAMES = {"public.xml", "attrs.xml", "ids.xml", "integers.xml", "styles.xml"}
    EXCLUDED_RESOURCE_PREFIXES = ("avd_", "$avd_")
    EXCLUDED_XML_ROOT_TAGS = {"animated-vector", "vector"}
    XML_NAME_ATTRIBUTES = {"name", "id", "type"}
    KNOWN_SECRET_VALUE_PATTERNS = {
        "possible_api_key": (
            re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
            re.compile(r"pk_(?:live|test)_[0-9A-Za-z]{16,}"),
        ),
        "possible_secret": (re.compile(r"sk_(?:live|test)_[0-9A-Za-z]{16,}"),),
        "possible_token": (re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"),),
        "possible_password": (),
        "possible_firebase": (re.compile(r"1:\d{6,}:android:[0-9a-fA-F]{16,}"),),
    }
    EXTENSIONS = {".java", ".kt", ".xml", ".json", ".properties", ".gradle", ".smali"}
    GENERIC_SECRET_MIN_LENGTH = 24
    GENERIC_SECRET_MIN_ENTROPY = 3.5
    MAX_FILE_BYTES = 1024 * 1024
    MAX_EVIDENCE = 80

    def extract(self, *roots: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if len(evidence) >= self.MAX_EVIDENCE:
                    return evidence
                if not path.is_file() or path.suffix.lower() not in self.EXTENSIONS:
                    continue
                if self._is_excluded_resource_file(path):
                    continue
                if path.stat().st_size > self.MAX_FILE_BYTES:
                    continue
                evidence.extend(self._scan_file(path))
                if len(evidence) >= self.MAX_EVIDENCE:
                    return evidence[: self.MAX_EVIDENCE]
        return evidence

    def _scan_file(self, path: Path) -> list[EvidenceItem]:
        if path.suffix.lower() == ".xml":
            return self._scan_xml_file(path)

        results: list[EvidenceItem] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return results
        for line_number, line in enumerate(lines, start=1):
            candidate_value = self._extract_assignment_value(line)
            if candidate_value is None:
                continue
            results.extend(self._evidence_for_value(path, line_number, line, candidate_value))
        return results

    @staticmethod
    def _is_excluded_resource_file(path: Path) -> bool:
        filename = path.name.lower()
        if filename in CodeSecretEvidenceExtractor.EXCLUDED_RESOURCE_FILENAMES:
            return True
        return filename.endswith(".xml") and filename.startswith(CodeSecretEvidenceExtractor.EXCLUDED_RESOURCE_PREFIXES)

    def _scan_xml_file(self, path: Path) -> list[EvidenceItem]:
        results: list[EvidenceItem] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            root = ET.fromstring(content)
        except (OSError, ET.ParseError):
            return results
        if self._local_name(root.tag) in self.EXCLUDED_XML_ROOT_TAGS:
            return results

        line_lookup = self._line_lookup(content)
        for element in root.iter():
            if element.text and element.text.strip():
                value = element.text.strip()
                line_number = line_lookup(value)
                context = f"<{self._local_name(element.tag)}>{value}</{self._local_name(element.tag)}>"
                results.extend(
                    self._evidence_for_value(
                        path,
                        line_number,
                        context,
                        value,
                        xml_value=True,
                        hint_text=str(element.attrib.get("name") or ""),
                    )
                )

            for attr_name, attr_value in element.attrib.items():
                local_name = self._local_name(attr_name)
                if local_name in self.XML_NAME_ATTRIBUTES or not attr_value.strip():
                    continue
                line_number = line_lookup(attr_value)
                context = f'{local_name}="{attr_value}"'
                results.extend(
                    self._evidence_for_value(
                        path,
                        line_number,
                        context,
                        attr_value,
                        xml_value=True,
                        hint_text=local_name,
                    )
                )
        return results

    def _evidence_for_value(
        self,
        path: Path,
        line_number: int,
        context: str,
        candidate_value: str,
        xml_value: bool = False,
        hint_text: str = "",
    ) -> list[EvidenceItem]:
        results: list[EvidenceItem] = []
        for evidence_type, needles in self.SECRET_KEYWORDS.items():
            confidence = self._confidence(evidence_type, needles, candidate_value, xml_value, hint_text)
            if confidence is None:
                continue
            results.append(
                EvidenceItem(
                    category=EvidenceCategory.code_secret,
                    evidence_type=evidence_type,
                    label=f"{evidence_type} in {path.name}:{line_number}",
                    value={
                        "file": str(path),
                        "line": line_number,
                        "matched_context": self._redact(context.strip()),
                        "matched_value": self._redact(candidate_value.strip()),
                        "confidence": confidence,
                    },
                    source_path=path,
                    source_node=f"line:{line_number}",
                )
            )
        return results

    def _confidence(
        self,
        evidence_type: str,
        needles: tuple[str, ...],
        candidate_value: str,
        xml_value: bool,
        hint_text: str = "",
    ) -> str | None:
        value = candidate_value.strip()
        if self._looks_like_code_reference(value) or self._looks_like_vector_path_data(value):
            return None
        lowered = value.lower()
        lowered_hint = hint_text.lower()
        has_keyword = any(needle in lowered for needle in needles)
        has_hint_keyword = any(needle in lowered_hint for needle in needles)
        has_known_shape = any(pattern.search(value) for pattern in self.KNOWN_SECRET_VALUE_PATTERNS[evidence_type])
        has_generic_shape = self._has_generic_secret_shape(value)

        if evidence_type == "possible_firebase":
            return "high" if has_known_shape else None
        if has_known_shape or ((has_keyword or has_hint_keyword) and has_generic_shape):
            return "high"
        if not xml_value and has_keyword and len(value) >= 8:
            return "low"
        return None

    @staticmethod
    def _extract_assignment_value(line: str) -> str | None:
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*")):
            return None
        match = re.search(r"(?:=|:)\s*['\"]?([^'\";,)\]}]+)", stripped)
        if not match:
            return None
        value = match.group(1).strip()
        return value or None

    @staticmethod
    def _has_generic_secret_shape(value: str) -> bool:
        normalized = value.strip().strip("'\"")
        if len(normalized) < CodeSecretEvidenceExtractor.GENERIC_SECRET_MIN_LENGTH:
            return False
        if not any(char.isalpha() for char in normalized) or not any(char.isdigit() for char in normalized):
            return False
        return CodeSecretEvidenceExtractor._entropy(normalized) >= CodeSecretEvidenceExtractor.GENERIC_SECRET_MIN_ENTROPY

    @staticmethod
    def _looks_like_code_reference(value: str) -> bool:
        normalized = value.strip()
        return (
            normalized.startswith(("Lcom/", "Ljava/", "Ljavax/", "Landroid/", "Lkotlin/", "Lb/"))
            or "->" in normalized
            or re.search(r"\b(?:com|android|java|javax|kotlin|google|firebase)/[A-Za-z0-9_/;$]+", normalized) is not None
        )

    @staticmethod
    def _looks_like_vector_path_data(value: str) -> bool:
        normalized = value.strip()
        if len(normalized) < 24:
            return False
        command_count = len(re.findall(r"[MmLlHhVvCcSsQqTtAaZz]", normalized))
        comma_count = normalized.count(",")
        return command_count >= 4 and comma_count >= 4

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        frequencies = {char: value.count(char) for char in set(value)}
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in frequencies.values())

    @staticmethod
    def _line_lookup(content: str):
        line_starts = [0]
        line_starts.extend(index + 1 for index, char in enumerate(content) if char == "\n")
        search_start = 0
        cached_lines: dict[str, int] = {}

        def lookup(value: str) -> int:
            nonlocal search_start
            if value in cached_lines:
                return cached_lines[value]

            match_index = content.find(value, search_start)
            if match_index < 0:
                match_index = content.find(value)
            if match_index < 0:
                line_number = 1
            else:
                line_number = bisect_right(line_starts, match_index)
                search_start = match_index + len(value)
            cached_lines[value] = line_number
            return line_number

        return lookup

    @staticmethod
    def _local_name(name: str) -> str:
        return name.rsplit("}", 1)[-1] if "}" in name else name

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 120:
            return value
        return value[:117] + "..."
