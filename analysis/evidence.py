from dataclasses import dataclass, replace
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


def _normalized_source_path(path: Path) -> str:
    parts = list(Path(path).parts)
    for tool in ("apktool", "jadx"):
        if tool not in parts:
            continue
        relative = parts[parts.index(tool) + 1:]
        if tool == "jadx" and relative[:1] == ["resources"]:
            relative = relative[1:]
        return "/".join(relative)
    return str(path)


def _source_tool(path: Path) -> str | None:
    parts = set(Path(path).parts)
    if "apktool" in parts:
        return "apktool"
    if "jadx" in parts:
        return "jadx"
    return None


def normalize_evidence_items(items: list[EvidenceItem]) -> tuple[list[EvidenceItem], dict[str, int]]:
    """Merge equivalent secret records while accounting for every input record."""
    groups: dict[tuple[object, ...], list[EvidenceItem]] = {}
    for item in items:
        if item.category != EvidenceCategory.code_secret:
            continue
        value = item.value
        tool = _source_tool(item.source_path)
        normalized_source = _normalized_source_path(item.source_path)
        if tool is None or value.get("matched_value") is None or value.get("line") is None:
            continue
        key = (
            item.evidence_type,
            value.get("matched_value"),
            str(value.get("line")),
            normalized_source,
            item.source_node,
        )
        groups.setdefault(key, []).append(item)

    normalized: list[EvidenceItem] = []
    cross_tool_duplicates_removed = 0
    same_tool_duplicates_removed = 0
    for item in items:
        if item.category != EvidenceCategory.code_secret:
            normalized.append(item)
            continue
        value = item.value
        tool = _source_tool(item.source_path)
        normalized_source = _normalized_source_path(item.source_path)
        key = (
            item.evidence_type,
            value.get("matched_value"),
            str(value.get("line")),
            normalized_source,
            item.source_node,
        )
        group = groups.get(key) if tool is not None and value.get("matched_value") is not None and value.get("line") is not None else None
        if not group:
            normalized.append(item)
            continue
        if group[0] is not item:
            continue
        tools = {_source_tool(candidate.source_path) for candidate in group}
        tools.discard(None)
        if len(group) == 1:
            normalized.append(item)
            continue
        if len(tools) < 2 and len(group) > 1:
            same_tool_duplicates_removed += len(group) - 1
        elif len(tools) >= 2:
            same_tool_removed = sum(
                max(0, sum(_source_tool(candidate.source_path) == current_tool for candidate in group) - 1)
                for current_tool in tools
            )
            same_tool_duplicates_removed += same_tool_removed
            cross_tool_duplicates_removed += len(group) - 1 - same_tool_removed
        references = [
            {
                "label": candidate.label,
                "source_path": str(candidate.source_path),
                "source_node": candidate.source_node,
                "tool": _source_tool(candidate.source_path),
            }
            for candidate in group
        ]
        merged_value = {**value, "source_references": references, "source_tools": sorted(tools)}
        source_label = "cross-tool sources" if len(tools) >= 2 else "duplicate sources"
        normalized.append(replace(item, value=merged_value, label=f"{item.evidence_type} in {Path(normalized_source).name}:{value.get('line')} ({source_label}: {', '.join(sorted(tools))})"))
    return normalized, {
        "raw_count": len(items),
        "normalized_count": len(normalized),
        "cross_tool_duplicates_removed": cross_tool_duplicates_removed,
        "same_tool_duplicates_removed": same_tool_duplicates_removed,
    }


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
            target_sdk = self._uses_sdk_value(root, "targetSdkVersion")
            evidence.extend(self._application_flags(application, manifest_path, target_sdk, apktool_output_path))
            evidence.extend(self._components(application, manifest_path, target_sdk))

        return evidence

    def _permissions(self, root: ET.Element, manifest_path: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
            for permission in root.findall(tag):
                name = self._android_attr(permission, "name")
                if not name:
                    continue
                is_dangerous = name in DANGEROUS_PERMISSIONS
                evidence.append(
                    EvidenceItem(
                        category=EvidenceCategory.permission,
                        evidence_type="dangerous_permission" if is_dangerous else "permission",
                        label=name,
                        value={"name": name, "dangerous": is_dangerous, "declaration_tag": tag},
                        source_path=manifest_path,
                        source_node=tag,
                    )
                )
        return evidence

    def _application_flags(
        self,
        application: ET.Element,
        manifest_path: Path,
        target_sdk: str | None,
        apktool_output_path: Path,
    ) -> list[EvidenceItem]:
        target = self._sdk_int(target_sdk)
        allow_backup = self._android_attr(application, "allowBackup")
        cleartext = self._android_attr(application, "usesCleartextTraffic")
        security_config = self._android_attr(application, "networkSecurityConfig")
        network_policy = self._network_security_policy(apktool_output_path, security_config, target)
        if network_policy["status"] == "enabled":
            cleartext_effective = "true"
        elif network_policy["status"] == "disabled":
            cleartext_effective = "false"
        else:
            cleartext_effective = None if security_config else (cleartext if cleartext is not None else ("false" if target is not None and target >= 28 else "true"))
        flags = {
            "debuggable": self._android_attr(application, "debuggable"),
            "allow_backup": allow_backup,
            "allow_backup_effective": allow_backup if allow_backup is not None else "true",
            "allow_backup_implicit": allow_backup is None,
            "uses_cleartext_traffic": cleartext,
            "uses_cleartext_traffic_effective": cleartext_effective,
            "uses_cleartext_traffic_implicit": cleartext is None,
            "target_sdk": target_sdk,
            "network_security_config": security_config,
            "network_security_policy": network_policy,
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

    def _components(self, application: ET.Element, manifest_path: Path, target_sdk: str | None) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for tag, component_type in self.COMPONENT_TAGS.items():
            for component in application.findall(tag):
                name = self._android_attr(component, "name")
                exported = self._android_attr(component, "exported")
                intent_filters = component.findall("intent-filter")
                exported_implicit = (
                    exported is None
                    and component_type != "content_provider"
                    and bool(intent_filters)
                )
                target = self._sdk_int(target_sdk)
                exported_required_for_install = bool(exported is None and intent_filters and target is not None and target >= 31)
                exported_effective = exported == "true" or (exported_implicit and not exported_required_for_install)
                evidence.append(
                    EvidenceItem(
                        category=EvidenceCategory.component,
                        evidence_type=component_type,
                        label=name or f"Unnamed {component_type}",
                        value={
                            "name": name,
                            "component_type": component_type,
                            "manifest_tag": tag,
                            "exported": exported,
                            "exported_effective": exported_effective,
                            "exported_implicit": exported_implicit,
                            "exported_default_rule": "intent-filter implies exported for legacy platform behavior" if exported_implicit else None,
                            "exported_required_for_install": exported_required_for_install,
                            "exported_installation_invalid": exported_required_for_install,
                            "target_sdk": target_sdk,
                            "launcher_entry": self._launcher_entry(component_type, intent_filters),
                            "intent_filter_count": len(intent_filters),
                            "permission": self._android_attr(component, "permission"),
                            "read_permission": self._android_attr(component, "readPermission"),
                            "write_permission": self._android_attr(component, "writePermission"),
                            "grant_uri_permissions": self._android_attr(component, "grantUriPermissions"),
                            "authorities": self._android_attr(component, "authorities"),
                        },
                        source_path=manifest_path,
                        source_node=tag,
                    )
                )
                evidence.extend(self._deep_links(name, component_type, intent_filters, manifest_path))
        return evidence

    def _launcher_entry(self, component_type: str, intent_filters: list[ET.Element]) -> bool:
        if component_type not in {"activity", "activity_alias"}:
            return False
        for intent_filter in intent_filters:
            actions = {
                self._android_attr(action, "name")
                for action in intent_filter.findall("action")
            }
            categories = {
                self._android_attr(category, "name")
                for category in intent_filter.findall("category")
            }
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                return True
        return False

    def _deep_links(
        self,
        component_name: str | None,
        component_type: str,
        intent_filters: list[ET.Element],
        manifest_path: Path,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        data_attributes = ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "pathAdvancedPattern", "mimeType", "schemeSpecificPart")
        for filter_index, intent_filter in enumerate(intent_filters, start=1):
            data_elements = []
            for data in intent_filter.findall("data"):
                attributes = {name: self._android_attr(data, name) for name in data_attributes}
                if any(attributes.values()):
                    data_elements.append({key: value for key, value in attributes.items() if value is not None})
            if not data_elements:
                continue
            # Android merges all <data> elements in one intent-filter into one
            # matcher.  They are not independent scheme/host routes: a scheme
            # declared in one element can combine with a host declared in
            # another, and every declared value in a matcher is an alternative.
            schemes = sorted({str(item["scheme"]) for item in data_elements if item.get("scheme")})
            hosts = sorted({str(item["host"]) for item in data_elements if item.get("host")})
            ports = sorted({str(item["port"]) for item in data_elements if item.get("port")})
            mime_types = sorted({str(item["mimeType"]) for item in data_elements if item.get("mimeType")})
            scheme_specific_parts = sorted({str(item["schemeSpecificPart"]) for item in data_elements if item.get("schemeSpecificPart")})
            path_constraints = [
                {"kind": path_key, "value": str(item[path_key])}
                for item in data_elements
                for path_key in ("path", "pathPrefix", "pathPattern", "pathAdvancedPattern")
                if item.get(path_key)
            ]
            paths = sorted({constraint["value"] for constraint in path_constraints})
            # Keep path kind in the route so a prefix/pattern is not presented
            # as an exact path.  The cartesian product reflects Android's
            # merged matcher and makes ambiguity explicit when a constraint is
            # absent rather than inventing an element-local pairing.
            routes = [
                {
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "path": path["value"] if path else None,
                    "path_kind": path["kind"] if path else None,
                    "mime_type": mime_type,
                    "scheme_specific_part": scheme_specific_part,
                }
                for scheme in (schemes or [None])
                for host in (hosts or [None])
                for port in (ports or [None])
                for path in (path_constraints or [None])
                for mime_type in (mime_types or [None])
                for scheme_specific_part in (scheme_specific_parts or [None])
            ]
            scheme = schemes[0] if len(schemes) == 1 else None
            host = hosts[0] if len(hosts) == 1 else None
            path = paths[0] if len(paths) == 1 else None
            wildcard = any(
                not route["scheme"] or not route["host"] or any("*" in str(route.get(key) or "") for key in ("scheme", "host", "path"))
                for route in routes
            )
            actions = sorted(filter(None, (self._android_attr(action, "name") for action in intent_filter.findall("action"))))
            categories = sorted(filter(None, (self._android_attr(category, "name") for category in intent_filter.findall("category"))))
            label = f"{scheme or '*'}://{host or '*'}{path or ''}"
            evidence.append(
                EvidenceItem(
                    category=EvidenceCategory.deep_link,
                    evidence_type="deep_link",
                    label=label,
                    value={
                        "component_name": component_name,
                        "component_type": component_type,
                        "scheme": scheme,
                        "host": host,
                        "path": path,
                        "mime_type": mime_types[0] if len(mime_types) == 1 else None,
                        "mime_types": mime_types,
                        "ports": ports,
                        "path_constraints": path_constraints,
                        "scheme_specific_parts": scheme_specific_parts,
                        "actions": actions,
                        "categories": categories,
                        "data_elements": data_elements,
                        "routes": routes,
                        "filter_index": filter_index,
                        "scope": "wildcard_or_missing_constraint" if wildcard else "explicit_scheme_host",
                    },
                    source_path=manifest_path,
                    source_node=f"intent-filter[{filter_index}]/data",
                )
            )
        return evidence

    def _network_security_policy(self, apktool_output_path: Path, reference: str | None, target_sdk: int | None) -> dict[str, object]:
        if not reference:
            return {"status": "not_configured", "source": None, "domain_policies": []}
        resource_name = reference.rsplit("/", 1)[-1].replace("@xml/", "")
        candidates = [
            apktool_output_path / "res" / "xml" / f"{resource_name}.xml",
            apktool_output_path / "res" / "xml" / resource_name,
        ]
        config_path = next((candidate for candidate in candidates if candidate.exists()), None)
        if config_path is None:
            return {"status": "unknown", "source": reference, "reason": "Referenced network security configuration was not found."}
        try:
            root = ET.parse(config_path).getroot()
        except (ET.ParseError, OSError) as exc:
            return {"status": "unknown", "source": str(config_path), "reason": f"Could not parse network security configuration: {exc}"}
        default = "false" if target_sdk is not None and target_sdk >= 28 else "true"
        base = root.find("base-config")
        base_policy = self._android_attr(base, "cleartextTrafficPermitted") if base is not None else default
        domain_policies = []

        def collect_domain_configs(parent: ET.Element, inherited_policy: str, parent_domains: list[str]) -> None:
            for domain_config in parent.findall("domain-config"):
                configured_policy = self._android_attr(domain_config, "cleartextTrafficPermitted")
                policy = configured_policy if configured_policy is not None else inherited_policy
                domains = [self._android_attr(domain, "includeSubdomains") or "false" for domain in domain_config.findall("domain")]
                names = [domain.text for domain in domain_config.findall("domain") if domain.text]
                domain_policies.append(
                    {
                        "domains": names,
                        "include_subdomains": domains,
                        "cleartext": policy,
                        "inherited": configured_policy is None,
                        "parent_domains": parent_domains,
                    }
                )
                collect_domain_configs(domain_config, policy, parent_domains + names)

        collect_domain_configs(root, str(base_policy), [])
        values = {str(base_policy).lower(), *(str(item["cleartext"]).lower() for item in domain_policies)}
        status = "mixed" if len(values) > 1 else ("enabled" if "true" in values else "disabled")
        return {"status": status, "source": str(config_path), "base_cleartext": base_policy, "domain_policies": domain_policies}

    @staticmethod
    def _android_attr(element: ET.Element | None, name: str) -> str | None:
        return element.attrib.get(f"{ANDROID_NS}{name}") if element is not None else None

    def _uses_sdk_value(self, root: ET.Element, name: str) -> str | None:
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is None:
            return None
        return self._android_attr(uses_sdk, name)

    @staticmethod
    def _sdk_int(value: str | None) -> int | None:
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None


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

    def __init__(self) -> None:
        self.limit_metadata = {
            "max_evidence": self.MAX_EVIDENCE,
            "emitted": 0,
            "truncated": False,
            "files_seen": 0,
            "files_scanned": 0,
            "files_skipped_size": 0,
            "unreadable_files": 0,
            "unreadable_file_samples": [],
        }

    def extract(self, *roots: Path) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                self.limit_metadata["files_seen"] += 1
                if len(evidence) >= self.MAX_EVIDENCE:
                    self.limit_metadata.update(emitted=len(evidence), truncated=True)
                    return evidence
                try:
                    is_candidate = path.is_file() and path.suffix.lower() in self.EXTENSIONS
                    size = path.stat().st_size if is_candidate else 0
                except OSError:
                    self._record_unreadable(path)
                    continue
                if not is_candidate:
                    continue
                if self._is_excluded_resource_file(path):
                    continue
                if size > self.MAX_FILE_BYTES:
                    self.limit_metadata["files_skipped_size"] += 1
                    continue
                self.limit_metadata["files_scanned"] += 1
                evidence.extend(self._scan_file(path))
                if len(evidence) >= self.MAX_EVIDENCE:
                    self.limit_metadata.update(emitted=self.MAX_EVIDENCE, truncated=True)
                    return evidence[: self.MAX_EVIDENCE]
        self.limit_metadata["emitted"] = len(evidence)
        return evidence

    def _scan_file(self, path: Path) -> list[EvidenceItem]:
        if path.suffix.lower() == ".xml":
            return self._scan_xml_file(path)

        results: list[EvidenceItem] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            self._record_unreadable(path)
            return results
        for line_number, line in enumerate(lines, start=1):
            candidate_value = self._extract_assignment_value(line)
            if candidate_value is None:
                continue
            results.extend(self._evidence_for_value(path, line_number, line, candidate_value))
        return results

    def _record_unreadable(self, path: Path) -> None:
        self.limit_metadata["unreadable_files"] += 1
        samples = self.limit_metadata["unreadable_file_samples"]
        if len(samples) < 10:
            samples.append(str(path))

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
