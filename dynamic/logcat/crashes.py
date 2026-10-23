from __future__ import annotations

from collections.abc import Iterable
import re

from .parser import parse_line


def detect_crashes(lines: Iterable[str], package: str, pids: Iterable[int]) -> list[dict[str, object]]:
    target_pids = {int(pid) for pid in pids}
    materialized = list(lines)
    parsed = [parse_line(line) for line in materialized]
    events: list[dict[str, object]] = []
    fatal_index: int | None = None
    for index, item in enumerate(parsed):
        message = item.message
        if item.tag and item.tag.strip() == "AndroidRuntime" and "FATAL EXCEPTION" in message:
            fatal_index = index
            continue
        if fatal_index is not None and index - fatal_index <= 20:
            process_match = re.search(r"Process:\s*([^,\s]+)", message)
            if process_match:
                if process_match.group(1) == package:
                    events.append({"type": "fatal_exception", "line": materialized[fatal_index], "detail": message, "pid": item.pid})
                fatal_index = None
        if re.search(rf"\bANR in\s+{re.escape(package)}\b", message):
            events.append({"type": "anr", "line": materialized[index], "detail": message, "pid": item.pid})
        died = re.search(rf"Process\s+{re.escape(package)}\s+\(pid\s+(\d+)\)\s+has died", message)
        if died:
            pid = int(died.group(1))
            if pid in target_pids:
                events.append({"type": "process_died", "line": materialized[index], "detail": message, "pid": pid})
        if item.pid in target_pids and ("Fatal signal" in message or (item.tag and item.tag.strip() == "DEBUG" and f">>> {package} <<<" in message)):
            events.append({"type": "native_fatal", "line": materialized[index], "detail": message, "pid": item.pid})
    return events
