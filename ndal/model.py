"""Jason Stys: strict immutable metadata models and native TSV/network-log trust boundaries."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_EVENTS — line 84
# variable: MAX_INPUT — line 85
# variable: ISSUE_CODES — line 86
# definition: Event — line 121
# variable: identifier — line 124
# variable: time_ns — line 125
# variable: src — line 126
# variable: dst — line 127
# variable: sport — line 128
# variable: dport — line 129
# variable: protocol — line 130
# variable: flags — line 131
# variable: bytes — line 132
# variable: name — line 133
# variable: response — line 134
# variable: rcode — line 135
# variable: qtype — line 136
# definition: Issue — line 140
# variable: packet — line 143
# variable: code — line 144
# definition: Finding — line 148
# variable: rule — line 151
# variable: subject — line 152
# variable: severity — line 153
# variable: explanation — line 154
# variable: measurement — line 155
# variable: evidence — line 156
# variable: total_evidence — line 157
# definition: integer — line 160
# parameter: high — line 160
# parameter: low — line 160
# parameter: value — line 160
# definition: address — line 167
# parameter: value — line 167
# definition: event — line 174
# parameter: value — line 174
# variable: identifier — line 178
# variable: high — line 188
# variable: key — line 188
# variable: low — line 188
# variable: key — line 201
# variable: name — line 204
# variable: label — line 209
# definition: unique_object — line 223
# parameter: pairs — line 223
# variable: result — line 225
# variable: key — line 226
# variable: value — line 226
# definition: logs — line 233
# parameter: data — line 233
# variable: result — line 237
# variable: seen — line 238
# variable: line — line 239
# variable: value — line 243
# variable: parsed — line 248
# definition: native — line 256
# parameter: data — line 256
# variable: lines — line 260
# variable: header — line 263
# variable: count — line 266
# variable: observations — line 267
# variable: issues — line 268
# variable: seen — line 269
# variable: issue_seen — line 270
# variable: line — line 271
# variable: fields — line 272
# variable: packet — line 274
# variable: is_dns — line 278
# variable: packet — line 305
# variable: pair — line 306
# variable: issue — line 313
# END CODE MAP

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

MAX_EVENTS = 20_000
MAX_INPUT = 8 * 1024 * 1024
ISSUE_CODES = frozenset(
    {
        "dns_truncated_message",
        "ipv4_reserved_flag",
        "timestamp_reordered",
        "capture_packet_truncated",
        "ethernet_truncated",
        "unsupported_ethertype",
        "ipv4_truncated",
        "ipv4_header",
        "ipv4_length",
        "ipv4_checksum",
        "unsupported_fragment",
        "udp_truncated",
        "udp_length",
        "udp_checksum",
        "tcp_truncated",
        "tcp_header",
        "tcp_checksum",
        "unsupported_transport",
        "unsupported_dns_tcp",
        "dns_truncated",
        "dns_pointer",
        "dns_label",
        "dns_name_limit",
        "dns_unsupported",
        "dns_record_limit",
        "dns_trailing",
        "dns_hop_limit",
        "truncated",
    }
)


@dataclass(frozen=True)
class Event:
    """Normalized flow/DNS metadata; identifier references a capture packet or explicit log ID."""

    identifier: str
    time_ns: int
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    flags: int
    bytes: int
    name: str | None = None
    response: bool | None = None
    rcode: int | None = None
    qtype: int | None = None


@dataclass(frozen=True)
class Issue:
    """A parser limitation/error with an exact packet reference, never raw bytes."""

    packet: int
    code: str


@dataclass(frozen=True)
class Finding:
    """Human-review hypothesis with rule, measurement, explanation and bounded evidence references."""

    rule: str
    subject: str
    severity: str
    explanation: str
    measurement: float
    evidence: tuple[str, ...]
    total_evidence: int


def integer(value: Any, low: int, high: int) -> int:
    """Require an actual integer (not bool/coercible text), within inclusive limits."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError("integer outside contract")
    return int(value)


def address(value: Any) -> str:
    """Accept only canonical IPv4 strings; never resolve hostnames or contact a network."""
    if not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value:
        raise ValueError("IPv4 required")
    return value


def event(value: dict[str, Any]) -> Event:
    """Validate a complete event with no missing/extra fields and coherent DNS metadata."""
    if set(value) != set(Event.__dataclass_fields__):
        raise ValueError("event fields mismatch")
    identifier = value["identifier"]
    if not isinstance(identifier, str) or not re.fullmatch(
        r"[a-zA-Z0-9_-]{1,64}", identifier
    ):
        raise ValueError("event ID invalid")
    if not isinstance(value["protocol"], str) or value["protocol"] not in {
        "udp",
        "tcp",
    }:
        raise ValueError("unsupported protocol")
    for key, low, high in [
        ("time_ns", 0, 4_294_967_295_999_999_999),
        ("sport", 0, 65535),
        ("dport", 0, 65535),
        ("flags", 0, 255),
        ("bytes", 0, 65535),
    ]:
        integer(value[key], low, high)
    address(value["src"])
    address(value["dst"])
    if value["protocol"] == "udp" and value["flags"] != 0:
        raise ValueError("UDP flags must be zero")
    if value["name"] is None:
        if any(value[key] is not None for key in ("response", "rcode", "qtype")):
            raise ValueError("partial DNS metadata")
    else:
        name = value["name"]
        if (
            not isinstance(name, str)
            or len(name) > 253
            or (name and not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", name))
            or any(len(label) > 63 for label in name.split("."))
        ):
            raise ValueError("DNS hostname invalid")
        if (
            value["protocol"] != "udp"
            or 53 not in {value["sport"], value["dport"]}
            or type(value["response"]) is not bool
        ):
            raise ValueError("DNS transport mismatch")
        integer(value["rcode"], 0, 15)
        integer(value["qtype"], 0, 65535)
    return Event(**value)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys instead of accepting ambiguous overwritten fields."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def logs(data: bytes) -> list[Event]:
    """Read strict bounded JSONL, unique IDs and exact Event schema; no arbitrary log-code execution."""
    if len(data) > MAX_INPUT:
        raise ValueError("log byte limit")
    result: list[Event] = []
    seen = set()
    for line in data.decode("utf-8").splitlines():
        if len(result) >= MAX_EVENTS or len(line) > 4096:
            raise ValueError("log event/line limit")
        try:
            value = json.loads(line, object_pairs_hook=unique_object)
        except RecursionError as error:
            raise ValueError("log nesting limit") from error
        if not isinstance(value, dict):
            raise ValueError("log object required")
        parsed = event(value)
        if parsed.identifier in seen or not parsed.identifier.startswith("log-"):
            raise ValueError("duplicate/non-log event ID")
        seen.add(parsed.identifier)
        result.append(parsed)
    return result


def native(data: str) -> tuple[int, list[Event], list[Issue]]:
    """Check versioned native TSV output with exact lengths, ranges, unique packets and issue codes."""
    if len(data) > 12 * 1024 * 1024:
        raise ValueError("native output limit")
    lines = data.splitlines()
    if not lines or len(lines) > MAX_EVENTS * 3 + 1:
        raise ValueError("native record limit")
    header = lines[0].split("\t")
    if len(header) != 3 or header[:2] != ["NDAL", "1"]:
        raise ValueError("native version mismatch")
    count = integer(int(header[2]), 0, MAX_EVENTS)
    observations = []
    issues = []
    seen: set[int] = set()
    issue_seen = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if fields[0] == "O" and len(fields) == 14:
            packet = integer(int(fields[1]), 1, count)
            if packet in seen:
                raise ValueError("duplicate packet")
            seen.add(packet)
            is_dns = fields[10] != "-"
            if not is_dns and fields[11:] != ["-", "-", "-"]:
                raise ValueError("partial native DNS")
            if is_dns and fields[11] not in {"0", "1"}:
                raise ValueError("native DNS response")
            observations.append(
                event(
                    asdict(
                        Event(
                            f"packet-{packet}",
                            int(fields[2]),
                            fields[3],
                            fields[4],
                            int(fields[5]),
                            int(fields[6]),
                            fields[7],
                            int(fields[8]),
                            int(fields[9]),
                            fields[10] if is_dns else None,
                            fields[11] == "1" if is_dns else None,
                            int(fields[12]) if is_dns else None,
                            int(fields[13]) if is_dns else None,
                        )
                    )
                )
            )
        elif fields[0] == "I" and len(fields) == 3:
            packet = integer(int(fields[1]), 1, count)
            pair = (packet, fields[2])
            if fields[2] not in ISSUE_CODES or pair in issue_seen:
                raise ValueError("unknown/duplicate issue")
            issue_seen.add(pair)
            issues.append(Issue(*pair))
        else:
            raise ValueError("native row invalid")
    if seen | {issue.packet for issue in issues} != set(range(1, count + 1)):
        raise ValueError("native packet accounting mismatch")
    return count, observations, issues
