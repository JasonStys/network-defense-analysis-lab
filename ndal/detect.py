"""Jason Stys: bounded explainable DNS/window/fan-out/periodicity hypotheses with scoped allowlists."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Policy — line 105
# variable: window_seconds — line 108
# variable: nxdomain_threshold — line 109
# variable: port_threshold — line 110
# variable: beacon_minimum — line 111
# variable: beacon_jitter — line 112
# variable: long_label — line 113
# variable: entropy_bits — line 114
# variable: allowed_connections — line 115
# variable: allowed_domains — line 116
# definition: policy — line 119
# parameter: value — line 119
# variable: high — line 123
# variable: key — line 123
# variable: low — line 123
# variable: key — line 131
# variable: lower — line 131
# variable: upper — line 131
# variable: key — line 138
# variable: item — line 141
# variable: expected — line 142
# definition: entropy — line 163
# parameter: label — line 163
# variable: count — line 168
# definition: finding — line 175
# parameter: explanation — line 176
# parameter: measurement — line 176
# parameter: rule — line 176
# parameter: subject — line 176
# parameter: values — line 176
# variable: value — line 185
# definition: window — line 190
# parameter: ports — line 190
# parameter: seconds — line 190
# parameter: values — line 190
# variable: active — line 192
# variable: counts — line 193
# variable: best_end — line 194
# variable: best_start — line 194
# variable: start — line 195
# variable: maximum — line 196
# variable: index — line 197
# variable: value — line 197
# variable: removed — line 199
# variable: start — line 200
# variable: score — line 206
# variable: maximum — line 208
# variable: best_end — line 209
# variable: best_start — line 209
# definition: detect — line 213
# parameter: events — line 213
# parameter: issues — line 213
# parameter: settings — line 213
# variable: dns_failures — line 217
# variable: ports — line 218
# variable: connections — line 219
# variable: output — line 220
# variable: allowed_names — line 221
# variable: item — line 221
# variable: allowed — line 222
# variable: item — line 224
# parameter: item — line 226
# variable: value — line 226
# variable: label — line 231
# variable: score — line 232
# variable: subject — line 251
# variable: values — line 251
# variable: peak — line 252
# variable: dst — line 263
# variable: src — line 263
# variable: values — line 263
# variable: peak — line 264
# variable: count — line 265
# variable: value — line 265
# variable: dst — line 276
# variable: port — line 276
# variable: src — line 276
# variable: values — line 276
# variable: intervals — line 279
# variable: left — line 281
# variable: right — line 281
# variable: average — line 283
# variable: jitter — line 286
# variable: grouped — line 297
# variable: issue — line 298
# variable: code — line 300
# variable: problem_values — line 300
# variable: item — line 308
# END CODE MAP

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

from ndal.model import MAX_EVENTS, Event, Finding, Issue, address, integer


@dataclass(frozen=True)
class Policy:
    """Tunable measurement thresholds, not threat intelligence or an automatic blocking policy."""

    window_seconds: int
    nxdomain_threshold: int
    port_threshold: int
    beacon_minimum: int
    beacon_jitter: float
    long_label: int
    entropy_bits: float
    allowed_connections: list[dict[str, Any]]
    allowed_domains: list[dict[str, Any]]


def policy(value: Any) -> Policy:
    """Fail closed on unknown/missing thresholds and unscoped/undocumented suppressions."""
    if not isinstance(value, dict) or set(value) != set(Policy.__dataclass_fields__):
        raise ValueError("policy fields mismatch")
    for key, low, high in [
        ("window_seconds", 1, 3600),
        ("nxdomain_threshold", 2, 1000),
        ("port_threshold", 2, 1000),
        ("beacon_minimum", 4, 1000),
        ("long_label", 8, 63),
    ]:
        integer(value[key], low, high)
    for key, lower, upper in [("beacon_jitter", 0.0, 1.0), ("entropy_bits", 0.0, 6.0)]:
        if (
            type(value[key]) not in {int, float}
            or not math.isfinite(value[key])
            or not lower <= value[key] <= upper
        ):
            raise ValueError("policy metric invalid")
    for key in ["allowed_connections", "allowed_domains"]:
        if not isinstance(value[key], list) or len(value[key]) > 100:
            raise ValueError("allowlist limit")
        for item in value[key]:
            expected = (
                {"src", "dst", "dport", "reason"}
                if key == "allowed_connections"
                else {"name", "reason"}
            )
            if (
                not isinstance(item, dict)
                or set(item) != expected
                or not isinstance(item["reason"], str)
                or not 5 <= len(item["reason"]) <= 200
            ):
                raise ValueError("allowlist scope/reason invalid")
            if key == "allowed_connections":
                address(item["src"])
                address(item["dst"])
                integer(item["dport"], 0, 65535)
            elif not isinstance(item["name"], str) or not 1 <= len(item["name"]) <= 253:
                raise ValueError("allowlist domain invalid")
    return Policy(**value)


def entropy(label: str) -> float:
    """Empirical character entropy in bits/character; short structured names can also score highly."""
    return (
        -sum(
            (count / len(label)) * math.log2(count / len(label))
            for count in Counter(label).values()
        )
        if label
        else 0.0
    )


def finding(
    rule: str, subject: str, values: list[Event], measurement: float, explanation: str
) -> Finding:
    """Retain the first 100 event IDs, total count and measured rationale for analyst review."""
    return Finding(
        rule,
        subject,
        "review",
        explanation,
        round(measurement, 6),
        tuple(value.identifier for value in values[:100]),
        len(values),
    )


def window(values: list[Event], seconds: int, ports: bool) -> list[Event]:
    """Sliding inclusive event-time window with a counted multiset; earliest maximum wins ties."""
    active: deque[Event] = deque()
    counts: Counter[int] = Counter()
    best_start, best_end = 0, 0
    start = 0
    maximum = 0
    for index, value in enumerate(values):
        while active and value.time_ns - active[0].time_ns > seconds * 1_000_000_000:
            removed = active.popleft()
            start += 1
            counts[removed.dport] -= 1
            if not counts[removed.dport]:
                del counts[removed.dport]
        active.append(value)
        counts[value.dport] += 1
        score = len(counts) if ports else len(active)
        if score > maximum:
            maximum = score
            best_start, best_end = start, index + 1
    return values[best_start:best_end]


def detect(events: list[Event], issues: list[Issue], settings: Policy) -> list[Finding]:
    """Analyze sorted bounded metadata; unrelated hosts cannot contribute to each other's score."""
    if len(events) > MAX_EVENTS * 2 or len(issues) > MAX_EVENTS * 2:
        raise ValueError("analysis event limit")
    dns_failures: dict[str, list[Event]] = defaultdict(list)
    ports: dict[tuple[str, str], list[Event]] = defaultdict(list)
    connections: dict[tuple[str, str, int], list[Event]] = defaultdict(list)
    output = []
    allowed_names = {item["name"] for item in settings.allowed_domains}
    allowed = {
        (item["src"], item["dst"], item["dport"])
        for item in settings.allowed_connections
    }
    for value in sorted(events, key=lambda item: (item.time_ns, item.identifier)):
        if value.name is not None and value.name not in allowed_names:
            if value.response and value.rcode == 3:
                dns_failures[value.dst].append(value)
            if not value.response:
                label = max(value.name.split("."), key=len)
                score = entropy(label)
                if len(label) >= settings.long_label and score >= settings.entropy_bits:
                    output.append(
                        finding(
                            "dns_long_label",
                            value.src,
                            [value],
                            score,
                            f"Label length {len(label)}; entropy {score:.3f} bits/character. Encoded telemetry and benign identifiers are alternative explanations; this is not proof of exfiltration.",
                        )
                    )
        # SYN without ACK only; SYN-ACK and ordinary response packets never count as initiations.
        if (
            value.protocol == "tcp"
            and value.flags & 0x12 == 0x02
            and (value.src, value.dst, value.dport) not in allowed
        ):
            ports[(value.src, value.dst)].append(value)
            connections[(value.src, value.dst, value.dport)].append(value)
    for subject, values in sorted(dns_failures.items()):
        peak = window(values, settings.window_seconds, False)
        if len(peak) >= settings.nxdomain_threshold:
            output.append(
                finding(
                    "dns_nxdomain_burst",
                    subject,
                    peak,
                    len(peak),
                    f"{len(peak)} NXDOMAIN responses in an inclusive {settings.window_seconds}s window. Resolver configuration errors and stale application names can also cause this.",
                )
            )
    for (src, dst), values in sorted(ports.items()):
        peak = window(values, settings.window_seconds, True)
        count = len({value.dport for value in peak})
        if count >= settings.port_threshold:
            output.append(
                finding(
                    "tcp_port_fanout",
                    f"{src} -> {dst}",
                    peak,
                    count,
                    f"{count} distinct destination ports in {settings.window_seconds}s. Approved inventory or diagnostics may explain this pattern; confirm authorization.",
                )
            )
    for (src, dst, port), values in sorted(connections.items()):
        if len(values) < settings.beacon_minimum:
            continue
        intervals = [
            (right.time_ns - left.time_ns) / 1e9
            for left, right in zip(values, values[1:], strict=False)
        ]
        average = mean(intervals)
        if average < 1:
            continue
        jitter = pstdev(intervals) / average
        if jitter <= settings.beacon_jitter:
            output.append(
                finding(
                    "tcp_periodicity",
                    f"{src} -> {dst}:{port}",
                    values,
                    jitter,
                    f"Interarrival mean {average:.3f}s, coefficient of variation {jitter:.4f}. Health checks, scheduled jobs and SYN retransmissions can be periodic; no payload or TCP reassembly is examined.",
                )
            )
    grouped: dict[str, list[Issue]] = defaultdict(list)
    for issue in issues:
        grouped[issue.code].append(issue)
    for code, problem_values in sorted(grouped.items()):
        output.append(
            Finding(
                "capture_quality",
                code,
                "coverage" if code.startswith("unsupported_") else "review",
                "Capture limitation or malformed evidence, not an attack attribution. See the parser contract before interpreting absent findings.",
                float(len(problem_values)),
                tuple(f"packet-{item.packet}" for item in problem_values[:100]),
                len(problem_values),
            )
        )
    return output
