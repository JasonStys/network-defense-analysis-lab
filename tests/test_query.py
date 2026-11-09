"""Jason Stys: independent keyset query, detector scope and capture-gap regression cases."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: fixture — line 43
# variable: rows — line 45
# definition: test_stable_pages_bound_snapshot_filters_and_missing_gaps — line 109
# variable: e — line 111
# variable: f — line 111
# variable: i — line 111
# variable: first — line 112
# variable: second — line 113
# variable: third — line 114
# variable: r — line 115
# variable: r — line 121
# variable: r — line 126
# variable: kwargs — line 129
# variable: selection — line 134
# variable: r — line 144
# definition: test_rejections — line 164
# parameter: kwargs — line 164
# definition: test_cursor_nonexistent_row_and_actual_cli — line 170
# parameter: tmp_path — line 170
# variable: e — line 172
# variable: f — line 172
# variable: i — line 172
# variable: r — line 173
# variable: cursor — line 174
# variable: source — line 183
# variable: out — line 185
# variable: value — line 203
# END CODE MAP

import base64
import json
from pathlib import Path

import pytest

from ndal.cli import main
from ndal.model import Event, Finding, Issue
from ndal.query import query


def fixture():
    """Three equal/different times in intentionally reverse order distinguish stable pages from input-order slicing."""
    rows = [
        Event(
            "log-c",
            2,
            "192.0.2.1",
            "192.0.2.2",
            1,
            80,
            "tcp",
            2,
            40,
            None,
            None,
            None,
            None,
        ),
        Event(
            "log-b",
            1,
            "192.0.2.1",
            "192.0.2.2",
            1,
            80,
            "tcp",
            2,
            40,
            None,
            None,
            None,
            None,
        ),
        Event(
            "log-a",
            1,
            "192.0.2.1",
            "192.0.2.2",
            1,
            53,
            "udp",
            0,
            40,
            None,
            None,
            None,
            None,
        ),
    ]
    return (
        rows,
        [Issue(5, "capture_packet_truncated")],
        [
            Finding(
                "tcp_periodicity",
                "fictional",
                "review",
                "whole snapshot",
                0.0,
                ("log-b", "log-c"),
                2,
            )
        ],
    )


def test_stable_pages_bound_snapshot_filters_and_missing_gaps():
    """Equal timestamps do not duplicate/lose IDs; capture gaps remain visible on every page and empty selection."""
    e, i, f = fixture()
    first = query(e, i, f, limit=1)
    second = query(e, i, f, limit=1, cursor=first["next_cursor"])
    third = query(e, i, f, limit=1, cursor=second["next_cursor"])
    assert [r["events"][0]["identifier"] for r in (first, second, third)] == [
        "log-a",
        "log-b",
        "log-c",
    ]
    assert third["next_cursor"] is None and all(
        r["total_matches"] == 3 for r in (first, second, third)
    )
    assert all(
        r["capture_issues_unfiltered"]
        == [{"packet": 5, "code": "capture_packet_truncated"}]
        for r in (first, second, third)
    )
    assert query(e, i, f, rule="absent")["events"] == []
    for kwargs in ({"protocol": "tcp"}, {"start_ns": 2}, {"end_ns": 1}):
        with pytest.raises(ValueError):
            query(e, i, f, cursor=first["next_cursor"], **kwargs)
    with pytest.raises(ValueError):
        query(e[:-1], i, f, cursor=first["next_cursor"])
    selection = query(
        e,
        i,
        f,
        protocol="tcp",
        rule="tcp_periodicity",
        severity="review",
        start_ns=1,
        end_ns=1,
    )
    assert [r["identifier"] for r in selection["events"]] == ["log-b"]
    assert selection["findings"][0]["total_evidence"] == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"limit": True},
        {"limit": 1001},
        {"start_ns": -1},
        {"end_ns": -1},
        {"protocol": "icmp"},
        {"severity": "high"},
        {"rule": "x' OR 1=1"},
        {"cursor": "!bad"},
        {"cursor": "a" * 1025},
        {"cursor": base64.urlsafe_b64encode(b"{}").decode()},
    ],
)
def test_rejections(kwargs):
    """All user filters/cursors are data, bounded and fail closed; no SQL interpolation or coercion."""
    with pytest.raises(ValueError):
        query(*fixture(), **kwargs)


def test_cursor_nonexistent_row_and_actual_cli(tmp_path: Path):
    """A copied scope hash cannot invent a continuation row; real log-only CLI emits both full and selected reports."""
    e, i, f = fixture()
    r = query(e, i, f, limit=1)
    cursor = json.loads(base64.urlsafe_b64decode(r["next_cursor"]))
    cursor["identifier"] = "absent"
    with pytest.raises(ValueError):
        query(
            e,
            i,
            f,
            cursor=base64.urlsafe_b64encode(json.dumps(cursor).encode()).decode(),
        )
    source = tmp_path / "demo"
    assert main(["demo", str(source)]) == 0
    out = tmp_path / "review"
    assert (
        main(
            [
                "analyze",
                "--logs",
                str(source / "connections.jsonl"),
                "--output",
                str(out),
                "--query",
                "--query-protocol",
                "tcp",
                "--query-limit",
                "2",
            ]
        )
        == 0
    )
    value = json.loads((out / "query.json").read_text())
    assert len(value["events"]) == 2 and value["next_cursor"]
    assert (out / "report.json").exists() and "default-src" in (
        out / "query.html"
    ).read_text()
