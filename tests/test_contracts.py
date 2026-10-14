"""Jason Stys: fail-closed wire/log/policy contracts, boundary semantics and bounded evidence property tests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: example — line 88
# parameter: updates — line 88
# variable: value — line 90
# definition: test_event_rejections — line 118
# parameter: key — line 118
# parameter: value — line 118
# definition: test_event_dns_contract — line 124
# variable: valid — line 126
# variable: changes — line 130
# definition: test_oversized_policy_integer — line 152
# variable: base — line 154
# definition: test_logs_reject — line 163
# parameter: data — line 163
# definition: test_log_limits_ids — line 169
# variable: line — line 173
# variable: data — line 179
# variable: index — line 181
# definition: test_json_nesting_failure — line 190
# parameter: monkeypatch — line 190
# definition: fail — line 193
# parameter: args — line 193
# parameter: kwargs — line 193
# definition: test_allowlist_hostnames — line 202
# variable: base — line 204
# variable: name — line 205
# definition: test_native_contract — line 231
# parameter: data — line 231
# definition: test_native_row_edges — line 237
# variable: row — line 239
# variable: bad — line 241
# definition: test_policy_limits — line 258
# variable: base — line 260
# variable: value — line 262
# definition: test_sliding_window_boundaries — line 280
# variable: values — line 282
# variable: index — line 284
# variable: port — line 284
# variable: second — line 284
# variable: value — line 288
# variable: value — line 293
# definition: test_beacon_alternatives_and_caps — line 302
# variable: base — line 304
# variable: times — line 305
# variable: events — line 306
# variable: i — line 308
# variable: t — line 308
# variable: result — line 315
# variable: index — line 318
# variable: result — line 323
# variable: index — line 324
# definition: test_jsonl_property — line 335
# parameter: data — line 335
# variable: values — line 338
# variable: value — line 341
# definition: test_root_dns_and_real_bounds — line 345
# variable: _ — line 349
# variable: events — line 349
# variable: issues — line 349
# END CODE MAP

from __future__ import annotations

import json
from dataclasses import asdict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ndal.cli import ROOT, decode
from ndal.detect import detect, entropy, finding, policy, window
from ndal.model import (
    MAX_INPUT,
    Event,
    Issue,
    address,
    event,
    integer,
    logs,
    native,
    unique_object,
)
from ndal.synthetic import log_sample, scenario


def example(**updates):
    """Create a known valid event then alter one independently controlled contract field."""
    value = asdict(
        Event("log-1", 0, "192.0.2.1", "192.0.2.2", 40000, 443, "tcp", 2, 40)
    )
    value.update(updates)
    return value


@pytest.mark.parametrize(
    "key,value",
    [
        ("identifier", "../../private"),
        ("identifier", 1),
        ("protocol", "icmp"),
        ("time_ns", True),
        ("sport", -1),
        ("dport", 65536),
        ("flags", 256),
        ("bytes", "40"),
        ("src", "localhost"),
        ("dst", "2001:db8::1"),
        ("name", "UPPER.example"),
        ("name", 1),
        ("name", "a" * 64),
        ("name", ".invalid"),
        ("response", True),
        ("rcode", 1),
    ],
)
def test_event_rejections(key, value):
    """No coercion, extra metadata or malformed hostnames enters the normalization layer."""
    with pytest.raises(ValueError):
        event(example(**{key: value}))


def test_event_dns_contract():
    """Coherent UDP DNS metadata supports the root name and rejects transport/type/range mismatches."""
    valid = example(
        protocol="udp", flags=0, dport=53, name="", response=False, rcode=0, qtype=1
    )
    assert event(valid).name == ""
    for changes in [
        {"response": 0},
        {"rcode": 16},
        {"qtype": -1},
        {"protocol": "tcp"},
        {"dport": 1},
        {"flags": 2},
        {"extra": 1},
        {"name": "a" * 254},
    ]:
        with pytest.raises(ValueError):
            event(valid | changes)
    with pytest.raises(ValueError):
        event({})
    with pytest.raises(ValueError):
        address(42)
    with pytest.raises(ValueError):
        integer(1.0, 0, 2)
    with pytest.raises(ValueError):
        event(example(protocol=[]))


def test_oversized_policy_integer():
    """Reject unbounded JSON integers before conversion to a finite float can overflow."""
    base = json.loads((ROOT / "config/default.json").read_text())
    with pytest.raises(ValueError, match="metric invalid"):
        policy(base | {"entropy_bits": 10**1000})


@pytest.mark.parametrize(
    "data",
    [b"{", b"[]", b"\xff", b'{"identifier":1,"identifier":2}', b" " * 4097, b"{}\n\n"],
)
def test_logs_reject(data):
    """Malformed encoding, JSON, nonobjects, duplicate keys and oversized lines are rejected."""
    with pytest.raises((ValueError, UnicodeError)):
        logs(data)


def test_log_limits_ids():
    """Exact maximum counts, duplicate IDs and non-log namespace cannot poison a merged snapshot."""
    with pytest.raises(ValueError):
        logs(b"x" * (MAX_INPUT + 1))
    line = json.dumps(example()).encode() + b"\n"
    with pytest.raises(ValueError, match="duplicate"):
        logs(line * 2)
    with pytest.raises(ValueError):
        logs(json.dumps(example(identifier="packet-1")).encode())
    # Use short objects: the explicit count check must fire before interpreting row 20,001.
    data = b"\n".join(
        json.dumps(example(identifier=f"log-{index}")).encode()
        for index in range(20001)
    )
    with pytest.raises(ValueError, match="event/line"):
        logs(data)
    assert unique_object([("safe", 1)]) == {"safe": 1}
    with pytest.raises(ValueError):
        logs(b"[" * 1500 + b"0" + b"]" * 1500)


def test_json_nesting_failure(monkeypatch):
    """Normalize a runtime JSON nesting failure consistently across Python parser implementations."""

    def fail(*args, **kwargs):
        """Emulate the parser's recursion boundary without depending on a platform-specific depth."""
        raise RecursionError("bounded parser test")

    monkeypatch.setattr(json, "loads", fail)
    with pytest.raises(ValueError, match="nesting"):
        logs(b"{}")


def test_allowlist_hostnames():
    """Only exact canonical DNS names are valid suppression values; wildcards cannot hide evidence."""
    base = json.loads((ROOT / "config/default.json").read_text())
    for name in ["*.example", "UPPER.example", "a..example", "a" * 64, ""]:
        with pytest.raises(ValueError, match="domain invalid"):
            policy(
                base
                | {
                    "allowed_domains": [
                        {"name": name, "reason": "Intentional negative test"}
                    ]
                }
            )


@pytest.mark.parametrize(
    "data",
    [
        "",
        "NDAL\t2\t0",
        "NDAL\t1",
        "NDAL\t1\t20001",
        "NDAL\t1\t1",
        "NDAL\t1\t0\nJUNK",
        "NDAL\t1\t1\nI\t1\tunknown",
        "NDAL\t1\t1\nI\t2\tdns_label",
        "NDAL\t1\t1\nI\t1\tdns_label\nI\t1\tdns_label",
    ],
)
def test_native_contract(data):
    """Version, accounting, issue allowlist, ranges and duplicate evidence are checked independently."""
    with pytest.raises(ValueError):
        native(data)


def test_native_row_edges():
    """Native observation fields cannot smuggle malformed DNS or duplicate packet records."""
    row = "O\t1\t0\t192.0.2.1\t192.0.2.2\t123\t53\tudp\t0\t40\t-\t-\t-\t-"
    assert native("NDAL\t1\t1\n" + row)[1][0].identifier == "packet-1"
    for bad in [
        row + "\textra",
        row.replace("-\t-\t-\t-", "-\t1\t0\t1"),
        row.replace("-\t-\t-\t-", "example\t2\t0\t1"),
        row + "\n" + row,
    ]:
        with pytest.raises(ValueError):
            native("NDAL\t1\t1\n" + bad)
    assert native("NDAL\t1\t1\n" + row.replace("-\t-\t-\t-", "example\t1\t3\t1"))[1][
        0
    ].response
    with pytest.raises(ValueError):
        native("x" * (12 * 1024 * 1024 + 1))
    with pytest.raises(ValueError):
        native("\n" * 60002)


def test_policy_limits():
    """Strict policy schema rejects NaN, booleans, unscoped exceptions and undocumented suppressions."""
    base = json.loads((ROOT / "config/default.json").read_text())
    assert policy(base).window_seconds == 60
    for value in [
        None,
        {},
        base | {"extra": 1},
        base | {"window_seconds": False},
        base | {"beacon_jitter": float("nan")},
        base | {"entropy_bits": "4"},
        base | {"entropy_bits": 7},
        base | {"allowed_connections": None},
        base | {"allowed_domains": [{}] * 101},
        base | {"allowed_connections": [{"src": "192.0.2.1"}]},
        base | {"allowed_domains": [{"name": 42, "reason": "explained"}]},
        base | {"allowed_domains": [{"name": "a", "reason": "no"}]},
    ]:
        with pytest.raises(ValueError):
            policy(value)


def test_sliding_window_boundaries():
    """Inclusive windows cross minute buckets, age out duplicates correctly and keep earliest maximum."""
    values = [
        event(example(identifier=f"log-{index}", time_ns=second * 10**9, dport=port))
        for index, (second, port) in enumerate(
            [(59, 1), (60, 1), (61, 2), (120, 3), (180, 4)]
        )
    ]
    assert [value.time_ns // 10**9 for value in window(values, 2, False)] == [
        59,
        60,
        61,
    ]
    assert [value.time_ns // 10**9 for value in window(values, 60, True)] == [
        60,
        61,
        120,
    ]
    assert not window([], 60, True)
    assert entropy("") == 0 and entropy("aaaa") == 0


def test_beacon_alternatives_and_caps():
    """Too-short, irregular and simultaneous event series don't meet the periodicity rule."""
    base = policy(json.loads((ROOT / "config/default.json").read_text()))
    for times in [[0, 1, 2], [0, 1, 2, 3, 4, 100], [0, 0, 0, 0, 0, 0]]:
        events = [
            event(example(identifier=f"log-{i}", time_ns=t * 10**9))
            for i, t in enumerate(times)
        ]
        assert not detect(events, [], base)
    with pytest.raises(ValueError):
        detect([event(example())] * 40001, [], base)
    with pytest.raises(ValueError):
        detect([], [Issue(1, "dns_label")] * 40001, base)
    result = finding(
        "test",
        "host",
        [event(example(identifier=f"log-{index}")) for index in range(101)],
        1.0,
        "explanation",
    )
    assert len(result.evidence) == 100 and result.total_evidence == 101
    result = detect(
        [], [Issue(index, "unsupported_transport") for index in range(1, 102)], base
    )[0]
    assert (
        result.severity == "coverage"
        and result.total_evidence == 101
        and len(result.evidence) == 100
    )


@given(st.binary(max_size=4096))
@settings(max_examples=200, deadline=None, derandomize=True)
def test_jsonl_property(data):
    """Bounded arbitrary log bytes return validated metadata or a controlled contract error."""
    try:
        values = logs(data)
    except (ValueError, UnicodeError):
        return
    for value in values:
        assert event(asdict(value)) == value


def test_root_dns_and_real_bounds():
    """Real native empty DNS hostname remains a legal root query, not a missing DNS sentinel."""
    from ndal.synthetic import dns, frame, pcap

    _, events, issues = decode(pcap([(0, frame(payload=dns("")))]))
    assert events[0].name == "" and not issues
    assert logs(log_sample()) and scenario("industrial_telemetry")
