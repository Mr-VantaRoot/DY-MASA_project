from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import re

from .parser import ParsedLine, parse_line, parse_uid


_START_PROC = re.compile(r"Start proc\s+(?P<pid>\d+):(?P<package>[^\s/:]+)(?::[^\s/]+)?(?:/[^\s]+)?")
_DIED = re.compile(r"Process\s+(?P<package>[^\s(]+)\s+\(pid\s+(?P<pid>\d+)\)\s+has died")
_KILLING = re.compile(r"Killing\s+(?P<pid>\d+):(?P<package>[^\s/]+)")
_PID_REFERENCE = re.compile(r"\bpid\s*(?:=|:|\s)\s*(\d+)\b", re.IGNORECASE)
_UID_REFERENCE = re.compile(r"\buid\s*(?:=|:|\s)\s*(\d+)\b", re.IGNORECASE)
_LIFECYCLE_TAGS = {"activitymanager", "activitytaskmanager", "packagemanager", "windowmanager"}


def _message(line: str) -> str:
    return parse_line(line).message


def discover_target_pids(lines: Iterable[str], package: str, seed_pids: Iterable[int | str] = ()) -> tuple[list[int], list[int]]:
    target_pids: list[int] = []
    target_uids: list[int] = []
    active: dict[int, str] = {}
    for seed in seed_pids:
        try:
            pid = int(seed)
        except (TypeError, ValueError):
            continue
        active[pid] = package
        if pid not in target_pids:
            target_pids.append(pid)

    for raw in lines:
        message = _message(raw)
        start = _START_PROC.search(message)
        if start:
            pid = int(start.group("pid"))
            started_package = start.group("package")
            if pid in active and active[pid] != started_package:
                del active[pid]
            if started_package == package:
                active[pid] = package
                if pid not in target_pids:
                    target_pids.append(pid)
                uid_match = re.search(r"/u(?P<user>\d+)(?:a(?P<app>\d+)|_(?P<name>a\d+))", message)
                if uid_match:
                    uid_value = parse_uid(f"u{uid_match.group('user')}_a{uid_match.group('app') or uid_match.group('name')}")
                    if uid_value is not None and uid_value not in target_uids:
                        target_uids.append(uid_value)

        died = _DIED.search(message)
        if died:
            pid = int(died.group("pid"))
            if died.group("package") == package:
                active.pop(pid, None)
        killing = _KILLING.search(message)
        if killing:
            pid = int(killing.group("pid"))
            if killing.group("package") == package:
                active.pop(pid, None)

    return target_pids, target_uids


def _references_target(parsed: ParsedLine, raw: str, package: str, pids: set[int], uids: set[int]) -> bool:
    message = parsed.message
    if parsed.tag and parsed.tag.strip().lower() in _LIFECYCLE_TAGS and package in raw:
        return True
    pid_values = {int(value) for value in _PID_REFERENCE.findall(raw)}
    uid_values = {int(value) for value in _UID_REFERENCE.findall(raw)}
    return bool(pid_values & pids or uid_values & uids)


def classify(lines: Iterable[str], package: str, pids: Iterable[int], uids: Iterable[int]) -> tuple[list[str], list[str], list[str]]:
    target_pids = {int(pid) for pid in pids}
    target_uids = {int(uid) for uid in uids}
    active: dict[int, str] = {pid: package for pid in target_pids}
    tier_a: list[str] = []
    tier_b: list[str] = []
    tier_c: list[str] = []
    for raw in lines:
        parsed = parse_line(raw)
        message = parsed.message
        start = _START_PROC.search(message)
        if start:
            pid = int(start.group("pid"))
            started_package = start.group("package")
            if pid in active and started_package != package:
                del active[pid]
            if started_package == package:
                active[pid] = package
                target_pids.add(pid)
        if parsed.pid is not None and parsed.pid in active and not parsed.header:
            tier_a.append(raw)
        elif not parsed.header and _references_target(parsed, raw, package, target_pids, target_uids):
            tier_b.append(raw)
        elif not parsed.header and package in raw:
            tier_c.append(raw)

        died = _DIED.search(message)
        if died and died.group("package") == package:
            active.pop(int(died.group("pid")), None)
        killing = _KILLING.search(message)
        if killing and killing.group("package") == package:
            active.pop(int(killing.group("pid")), None)
    return tier_a, tier_b, tier_c


def merge_tiers_in_order(lines: Iterable[str], *tiers: Iterable[str]) -> list[str]:
    """Merge selected tier lines in their original order, preserving duplicates."""
    wanted = Counter(line for tier in tiers for line in tier)
    merged: list[str] = []
    for line in lines:
        if wanted[line]:
            merged.append(line)
            wanted[line] -= 1
    return merged


def code_risk_matches(lines: Iterable[str]) -> list[str]:
    patterns = (
        re.compile(r"cleartext communication not permitted", re.IGNORECASE),
        re.compile(r"\bSSLHandshakeException\b"),
        re.compile(r"\bjavax\.net\.ssl\b"),
        re.compile(r"\bwebview\b", re.IGNORECASE),
        re.compile(r"http://(?!schemas\.android\.com)", re.IGNORECASE),
    )
    return [line for line in lines if any(pattern.search(line) for pattern in patterns)]
