"""Actual offline packet/log analysis, stable saved-snapshot pages and SQL evidence review. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 116
# variable: PRODUCT — line 117
# variable: PROFILE — line 117
# variable: TITLE — line 118
# variable: VERSION — line 118
# variable: COLUMNS — line 119
# variable: RESOURCES — line 125
# variable: RESOURCE_LIMITS — line 135
# variable: MODES — line 136
# variable: REVIEW_MODE — line 137
# variable: CHOICES — line 138
# variable: FIELDS — line 139
# variable: ACTIVE_FIELDS — line 152
# variable: _ — line 153
# variable: name — line 153
# variable: _ — line 154
# variable: name — line 154
# variable: SCENARIOS — line 156
# variable: HELP — line 164
# definition: scenario — line 171
# parameter: name — line 171
# parameter: state — line 171
# variable: index — line 175
# variable: case — line 176
# variable: prepared — line 184
# variable: data — line 187
# variable: path — line 187
# variable: stream — line 196
# definition: number — line 221
# parameter: lower — line 221
# parameter: upper — line 221
# parameter: value — line 221
# definition: analyze — line 233
# parameter: parameters — line 234
# parameter: stage — line 234
# parameter: state — line 234
# variable: mode — line 237
# variable: value — line 240
# variable: files — line 242
# variable: selected — line 244
# variable: events — line 245
# variable: issues — line 246
# variable: digests — line 247
# variable: raw — line 249
# variable: _ — line 251
# variable: events — line 251
# variable: issues — line 251
# variable: raw — line 253
# variable: events — line 255
# variable: findings — line 258
# variable: report — line 259
# variable: previous — line 269
# variable: report — line 270
# variable: events — line 271
# variable: row — line 271
# variable: issues — line 272
# variable: row — line 272
# variable: findings — line 273
# variable: row — line 273
# variable: files — line 274
# variable: data — line 276
# variable: name — line 276
# variable: start — line 279
# variable: end — line 280
# variable: limit — line 281
# variable: selected_page — line 282
# variable: connection — line 296
# variable: target — line 299
# variable: destination — line 301
# variable: _ — line 305
# variable: name — line 305
# variable: summary — line 307
# definition: next_page — line 311
# parameter: files — line 311
# variable: page — line 313
# variable: result — line 316
# definition: views — line 321
# parameter: files — line 321
# variable: page — line 323
# variable: report — line 323
# variable: value — line 324
# variable: item — line 331
# variable: name — line 331
# variable: found — line 337
# variable: row — line 354
# definition: cells — line 359
# parameter: row — line 359
# variable: detail — line 361
# variable: detail — line 363
# END CODE MAP

from __future__ import annotations

import hashlib
import sqlite3
import sys
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import cli
from .desktop_io import Rejected, canonical, json_value
from .desktop_state import Workspace, unlinked
from .detect import detect, policy
from .inputs import read_source
from .model import MAX_INPUT, Event, Finding, Issue, logs
from .query import query
from .report import document, render
from .store import database, search
from .synthetic import log_sample
from .synthetic import scenario as synthetic_capture

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "network-defense-analysis-lab", "NetworkDefenseAnalysisLab"
TITLE, VERSION = "Network Defense Analysis Workbench", "1.1.0"
COLUMNS = (
    "Time / subject / reference",
    "Rule / protocol",
    "Evidence / endpoints",
    "State / severity",
)
RESOURCES = (
    "config/default.json",
    "examples/desktop/custom-policy.json",
    "sql/schema.sql",
    "sql/search.sql",
    "native/packet-decoder.exe",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
RESOURCE_LIMITS: dict[str, int] = {}
MODES = ("Analyze authorized capture / logs", "Page selected saved evidence snapshot")
REVIEW_MODE = None
CHOICES = {"protocol": ("any", "udp", "tcp"), "severity": ("any", "review", "coverage")}
FIELDS = (
    ("capture", "Authorized classic PCAP file (optional)", "file"),
    ("logs", "Authorized normalized JSONL logs (optional; distinct source)", "file"),
    ("policy", "Detection thresholds / scoped allowlists JSON", "file"),
    ("search", "Exact IPv4 address or hostname SQL search (optional)", "text"),
    ("start", "Inclusive start time (integer nanoseconds)", "text"),
    ("end", "Inclusive end time (integer nanoseconds)", "text"),
    ("protocol", "Evidence protocol filter", "choice"),
    ("rule", "Exact finding rule (blank means all)", "text"),
    ("severity", "Finding severity filter", "choice"),
    ("limit", "Evidence page size (1 to 1000)", "text"),
    ("cursor", "Bound snapshot/filter cursor (blank for first page)", "text"),
)
ACTIVE_FIELDS = {
    MODES[0]: tuple(name for name, _, _ in FIELDS),
    MODES[1]: tuple(name for name, _, _ in FIELDS[3:]),
}
SCENARIOS = (
    "DNS response burst and independent connection logs",
    "Benign office lookup",
    "Industrial telemetry negative",
    "TCP port fan-out",
    "Malformed capture remains visible",
    "Custom higher DNS threshold",
)
HELP = """Analyze authorized local classic PCAP files and/or normalized JSONL logs using the actual bounded Rust wire decoder, original Python detectors and indexed SQLite searches. No capture driver, DNS query, scan, TLS decryption, attribution or automatic blocking occurs.
Prepared scenarios fill ordinary controls in this application. You may choose different supported files and policy JSON. Capture/log sources must be distinct: equivalent copies duplicate counts. Policy allowlists need explicit narrow scopes and reasons. Findings are hypotheses and missing findings do not establish safety.
The original detector always sees the full normalized snapshot. Time/protocol/rule/severity and page limits only select review evidence afterward. Capture issues have no reliable timestamps and remain visible on every page. Detector evidence references may be capped at 100; their counts stay explicit.
Open a completed saved analysis and choose Page selected saved evidence snapshot, or use Prepare next evidence page. Pages bind the complete saved events/findings and exact filters; changing filters requires clearing the cursor. No raw packet payloads are retained in saved bundles. SQL search is an exact bound value, not a wildcard or a query editor.
Saved analysis/history is local plaintext for the trusted OS owner, not encryption, multiuser authentication or proof of source acquisition. Keep exports private and back up the entire profile only after normal exit. The original CLI remains available with its own explicit custom paths."""


def scenario(name: str, state: Workspace) -> dict[str, str]:
    """Prepare original synthetic files only in the selected owner-local profile, never overwrite edited data."""
    if name not in SCENARIOS:
        raise Rejected("unknown_prepared_scenario")
    index = SCENARIOS.index(name)
    case = (
        "dns_burst",
        "office_baseline",
        "industrial_telemetry",
        "port_fanout",
        "truncated_packet",
        "dns_burst",
    )[index]
    prepared = state.path / "prepared-inputs"
    unlinked(prepared)
    prepared.mkdir(exist_ok=True, mode=0o700)
    for path, data in (
        (prepared / (case + ".pcap"), synthetic_capture(case)),
        (prepared / "connections.jsonl", log_sample()),
    ):
        unlinked(path)
        if path.exists():
            if read_source(path, MAX_INPUT) != data:
                raise Rejected("prepared_input_changed_use_explicit_custom_file")
        else:
            with path.open("xb") as stream:
                stream.write(data)
    return {
        "mode": MODES[0],
        "capture": str(prepared / (case + ".pcap")),
        "logs": str(prepared / "connections.jsonl") if index == 0 else "",
        "policy": str(
            ROOT
            / (
                "examples/desktop/custom-policy.json"
                if index == 5
                else "config/default.json"
            )
        ),
        "search": "192.0.2.10" if index == 0 else "",
        "start": "0",
        "end": str(2**63 - 1),
        "protocol": "any",
        "rule": "",
        "severity": "any",
        "limit": "2",
        "cursor": "",
    }


def number(value: str, lower: int, upper: int) -> int:
    """Require a finite bounded ASCII integer rather than accepting floats or current-clock defaults."""
    if (
        not value.isascii()
        or not value.isdecimal()
        or len(value) > 19
        or not lower <= int(value) <= upper
    ):
        raise Rejected("invalid_numeric_filter")
    return int(value)


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Invoke original whole-snapshot engines, then page/search the complete retained evidence without live traffic."""
    mode = parameters.get("mode")
    if mode not in MODES:
        raise Rejected("unsupported_offline_operation")
    if sum(len(value.encode("utf-8")) for value in parameters.values()) > 128 * 1024:
        raise Rejected("parameter_bound")
    files: dict[str, bytes] = {}
    if mode == MODES[0]:
        selected = policy(json_value(read_source(Path(parameters["policy"]), 65536)))
        events: list[Event] = []
        issues: list[Issue] = []
        digests: dict[str, str] = {}
        if parameters["capture"]:
            raw = read_source(Path(parameters["capture"]), MAX_INPUT)
            digests["capture"] = hashlib.sha256(raw).hexdigest()
            _, events, issues = cli.decode(raw, scratch=stage)
        if parameters["logs"]:
            raw = read_source(Path(parameters["logs"]), MAX_INPUT)
            digests["logs"] = hashlib.sha256(raw).hexdigest()
            events += logs(raw)
        if not digests:
            raise Rejected("select_capture_and_or_logs")
        findings = detect(events, issues, selected)
        report = document(events, issues, findings, selected, digests)
        report["policy_sha256"] = hashlib.sha256(
            canonical(asdict(selected))
        ).hexdigest()
        report["policy_hash_scope"] = (
            "Canonical validated thresholds/allowlists, not original source byte identity"
        )
        files["report.json"] = canonical(report)
        files["report.html"] = render(report).encode("utf-8")
    else:
        previous = state.files(number(parameters.get("_run", "0"), 1, 2**31 - 1))
        report = json_value(previous["report.json"])
        events = [Event(**row) for row in report["events"]]
        issues = [Issue(**row) for row in report["issues"]]
        findings = [Finding(**row) for row in report["findings"]]
        files = {
            name: data
            for name, data in previous.items()
            if name in ("report.json", "report.html")
        }
    start = number(parameters["start"], 0, 2**63 - 1)
    end = number(parameters["end"], start, 2**63 - 1)
    limit = number(parameters["limit"], 1, 1000)
    selected_page = query(
        events,
        issues,
        findings,
        start_ns=start,
        end_ns=end,
        protocol=None if parameters["protocol"] == "any" else parameters["protocol"],
        rule=parameters["rule"] or None,
        severity=None if parameters["severity"] == "any" else parameters["severity"],
        cursor=parameters["cursor"] or None,
        limit=limit,
    )
    files["query.json"] = canonical(selected_page)
    files["query.html"] = render(selected_page).encode("utf-8")
    with closing(database(events, issues)) as connection:
        if parameters["search"]:
            files["search.json"] = canonical(search(connection, parameters["search"]))
        target = stage / "evidence.sqlite"
        cli.write(target, b"")
        with closing(sqlite3.connect(target)) as destination:
            connection.backup(destination)
        files["evidence.sqlite"] = read_source(target, 32 * 1024 * 1024)
    files["page-context.json"] = canonical(
        {name: parameters[name] for name, _, _ in FIELDS[3:]}
    )
    summary = f"{len(events)} full events; {len(findings)} review hypotheses; {len(issues)} visible capture issues; page {len(selected_page['events'])}/{selected_page['total_matches']}"
    return mode, summary, files


def next_page(files: dict[str, bytes]) -> dict[str, str]:
    """Prepare the next real cursor with the saved exact filters; do not silently change the selected snapshot."""
    page = json_value(files["query.json"])
    if page["next_cursor"] is None:
        raise Rejected("no_next_evidence_page")
    result = json_value(files["page-context.json"])
    result.update(mode=MODES[1], cursor=page["next_cursor"])
    return dict(result)


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Present original full hypotheses, bounded query rows and unfiltered capture gaps as distinct evidence views."""
    report, page = json_value(files["report.json"]), json_value(files["query.json"])
    value = {
        "Original full-snapshot hypotheses": report["findings"],
        "Selected evidence page": page["events"],
        "Capture quality issues (unfiltered)": page["capture_issues_unfiltered"],
        "Page summary and cursor": [
            {
                name: item
                for name, item in page.items()
                if name not in ("events", "findings", "capture_issues_unfiltered")
            }
        ],
    }
    if "search.json" in files:
        found = json_value(files["search.json"])
        value["Exact SQL evidence search"] = [
            dict(
                zip(
                    (
                        "identifier",
                        "time_ns",
                        "src",
                        "dst",
                        "protocol",
                        "dport",
                        "name",
                    ),
                    row,
                    strict=True,
                )
            )
            for row in found
        ]
    return value


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Display exact original fields without implying that a review hypothesis establishes an attack."""
    detail = row.get("explanation", row.get("total_matches", ""))
    if "src" in row and "dst" in row:
        detail = f"{row['src']} → {row['dst']}:{row['dport']}"
    return (
        str(
            row.get(
                "time_ns",
                row.get("subject", row.get("packet", row.get("identifier", ""))),
            )
        ),
        str(row.get("rule", row.get("protocol", row.get("code", "")))),
        str(detail),
        str(row.get("severity", row.get("dst", row.get("snapshot_filter_sha256", "")))),
    )
