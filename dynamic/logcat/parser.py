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

    prefix, separator, message = body.partition(":")
    fields = prefix.split()
    if separator and len(fields) >= 3 and fields[0].isdigit() and fields[1].isdigit():
        pid, _tid = int(fields[0]), int(fields[1])
        remaining = fields[2:]
        level_index = next((index for index, field in enumerate(remaining) if field in "VDIWEFS"), None)
        if level_index is not None:
            level = remaining[level_index]
            before_level = remaining[:level_index]
            after_level = remaining[level_index + 1:]
            all_before_level = fields[: level_index + 2]
            numeric_before_level = [field for field in all_before_level if field.isdigit()]
            # A uid-first numeric layout (uid pid tid level) is ambiguous with
            # pid/tid/uid. Do not confidently classify the uid as the process ID.
            # The normal uid-after-tid layout has the first two numeric fields
            # equal, which remains safely supported.
            if (
                len(all_before_level) >= 3
                and all(field.isdigit() for field in all_before_level[:3])
                and all_before_level[0] != all_before_level[1]
            ):
                return ParsedLine(raw=raw, timestamp=timestamp, message=body)
            uid_token = next((field for field in before_level if parse_uid(field) is not None), None)
            if uid_token is None and after_level and parse_uid(after_level[0]) is not None and len(after_level) > 1:
                uid_token = after_level.pop(0)
            return ParsedLine(
                raw=raw,
                timestamp=timestamp,
                pid=pid,
                uid=parse_uid(uid_token),
                level=level,
                tag=" ".join(after_level) or None,
                message=message.lstrip(),
            )
    return ParsedLine(raw=raw, timestamp=timestamp, message=body)
