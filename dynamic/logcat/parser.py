from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ParsedLine:
    raw: str
    timestamp: str | None = None
    pid: int | None = None
    uid: int | None = None
    level: str | None = None
    tag: str | None = None
    message: str = ""
    header: bool = False


_TIMESTAMP = re.compile(
    r"^(?P<timestamp>(?:\d{2}-\d{2}(?:-\d{4})?|\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<body>.*)$"
)
_TIME_STYLE = re.compile(
    r"^(?P<level>[VDIWEFS])/(?P<tag>.*?)\(\s*(?P<pid>\d+)\s*\):\s?(?P<message>.*)$"
)
_THREAD_STYLE_WITH_UID = re.compile(
    r"^(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<uid>\S+)\s+(?P<level>[VDIWEFS])\s+(?P<tag>[^:]+):\s?(?P<message>.*)$"
)
_THREAD_STYLE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEFS])\s+(?P<tag>[^:]+):\s?(?P<message>.*)$"
)


def parse_uid(value: str | None) -> int | None:
    if not value:
        return None
    if value.isdigit():
        return int(value)
    match = re.fullmatch(r"u(?P<user>\d+)_a(?P<app>\d+)", value)
    if match:
        return int(match.group("user")) * 100000 + 10000 + int(match.group("app"))
    return None


def parse_line(raw: str) -> ParsedLine:
    if raw.startswith("---------"):
        return ParsedLine(raw=raw, message=raw, header=True)
    timestamp_match = _TIMESTAMP.match(raw)
    if not timestamp_match:
        return ParsedLine(raw=raw, message=raw)

    timestamp = timestamp_match.group("timestamp")
    body = timestamp_match.group("body")
    match = _TIME_STYLE.match(body)
    if match:
        return ParsedLine(
            raw=raw,
            timestamp=timestamp,
            pid=int(match.group("pid")),
            level=match.group("level"),
            tag=match.group("tag"),
            message=match.group("message"),
        )

    match = _THREAD_STYLE_WITH_UID.match(body)
    if not match:
        match = _THREAD_STYLE.match(body)
    if match:
        return ParsedLine(
            raw=raw,
            timestamp=timestamp,
            pid=int(match.group("pid")),
            uid=parse_uid(match.groupdict().get("uid")),
            level=match.group("level"),
            tag=match.group("tag"),
            message=match.group("message"),
        )
    return ParsedLine(raw=raw, timestamp=timestamp, message=body)
