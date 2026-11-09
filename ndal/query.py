"""Jason Stys: snapshot-bound analyst evidence drilldown with stable keyset pages and visible capture gaps."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: query — line 56
# parameter: events — line 57
# parameter: issues — line 58
# parameter: findings — line 59
# parameter: start_ns — line 61
# parameter: end_ns — line 62
# parameter: protocol — line 63
# parameter: rule — line 64
# parameter: severity — line 65
# parameter: cursor — line 66
# parameter: limit — line 67
# variable: c — line 82
# variable: filters — line 85
# variable: selected_findings — line 92
# variable: f — line 94
# variable: referenced — line 98
# variable: identifier — line 99
# variable: row — line 99
# variable: restrict — line 101
# variable: rows — line 102
# variable: e — line 105
# parameter: e — line 110
# variable: bound — line 112
# variable: e — line 115
# variable: i — line 116
# variable: f — line 117
# variable: after — line 124
# variable: value — line 129
# variable: r — line 144
# variable: after — line 147
# variable: remaining — line 148
# variable: r — line 149
# variable: page — line 151
# variable: next_cursor — line 152
# variable: last — line 154
# variable: next_cursor — line 155
# variable: page_ids — line 165
# variable: row — line 165
# variable: f — line 175
# variable: i — line 177
# END CODE MAP

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from typing import Any

from ndal.model import Event, Finding, Issue, integer, unique_object


def query(
    events: list[Event],
    issues: list[Issue],
    findings: list[Finding],
    *,
    start_ns: int = 0,
    end_ns: int = 2**63 - 1,
    protocol: str | None = None,
    rule: str | None = None,
    severity: str | None = None,
    cursor: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Filter a complete already-normalized snapshot; pages never rerun detections on a misleading event subset."""
    integer(start_ns, 0, 2**63 - 1)
    integer(end_ns, start_ns, 2**63 - 1)
    integer(limit, 1, 1000)
    if protocol not in (None, "udp", "tcp") or severity not in (
        None,
        "review",
        "coverage",
    ):
        raise ValueError("query filter invalid")
    if rule is not None and (
        not isinstance(rule, str)
        or not 1 <= len(rule) <= 80
        or not all(c.isalnum() or c == "_" for c in rule)
    ):
        raise ValueError("rule filter invalid")
    filters = {
        "start_ns": start_ns,
        "end_ns": end_ns,
        "protocol": protocol,
        "rule": rule,
        "severity": severity,
    }
    selected_findings = [
        asdict(f)
        for f in findings
        if (rule is None or f.rule == rule)
        and (severity is None or f.severity == severity)
    ]
    referenced = {
        identifier for row in selected_findings for identifier in row["evidence"]
    }
    restrict = rule is not None or severity is not None
    rows = sorted(
        (
            asdict(e)
            for e in events
            if start_ns <= e.time_ns <= end_ns
            and (protocol is None or e.protocol == protocol)
            and (not restrict or e.identifier in referenced)
        ),
        key=lambda e: (e["time_ns"], e["identifier"]),
    )
    bound = hashlib.sha256(
        json.dumps(
            {
                "events": [asdict(e) for e in events],
                "issues": [asdict(i) for i in issues],
                "findings": [asdict(f) for f in findings],
                "filters": filters,
            },
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    after: tuple[int, str] | None = None
    if cursor is not None:
        if not isinstance(cursor, str) or len(cursor) > 1024:
            raise ValueError("cursor invalid")
        try:
            value = json.loads(
                base64.b64decode(cursor, altchars=b"-_", validate=True),
                object_pairs_hook=unique_object,
            )
        except (ValueError, UnicodeError) as error:
            raise ValueError("cursor invalid") from error
        if (
            not isinstance(value, dict)
            or set(value) != {"snapshot", "time_ns", "identifier"}
            or value["snapshot"] != bound
        ):
            raise ValueError("cursor snapshot/filter mismatch")
        integer(value["time_ns"], start_ns, end_ns)
        if not isinstance(value["identifier"], str) or not any(
            (r["time_ns"], r["identifier"]) == (value["time_ns"], value["identifier"])
            for r in rows
        ):
            raise ValueError("cursor row mismatch")
        after = value["time_ns"], value["identifier"]
    remaining = [
        r for r in rows if after is None or (r["time_ns"], r["identifier"]) > after
    ]
    page = remaining[:limit]
    next_cursor = None
    if len(remaining) > limit:
        last = page[-1]
        next_cursor = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "snapshot": bound,
                    "time_ns": last["time_ns"],
                    "identifier": last["identifier"],
                },
                sort_keys=True,
            ).encode()
        ).decode()
    page_ids = {row["identifier"] for row in page}
    return {
        "schema": "ndal-query-v1",
        "author": "Jason Stys",
        "snapshot_filter_sha256": bound,
        "filters": filters,
        "total_matches": len(rows),
        "events": page,
        "next_cursor": next_cursor,
        "findings": [
            f for f in selected_findings if page_ids.intersection(f["evidence"])
        ],
        "capture_issues_unfiltered": [asdict(i) for i in issues],
        "scope": "Full-snapshot detector hypotheses retained; filtered evidence references may be capped by the original detector. No finding implies no safety guarantee. Capture issues lack reliable timestamps and remain unfiltered, not falsely assigned to this page. Cursor hashes bind snapshot/filters, not identity or authenticated evidence acquisition.",
    }
