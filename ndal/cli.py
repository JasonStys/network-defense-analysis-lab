"""Jason Stys: local bounded file analysis, synthetic demo generation and private no-overwrite evidence output."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 70
# definition: read — line 73
# parameter: maximum — line 73
# parameter: path — line 73
# definition: write — line 78
# parameter: data — line 78
# parameter: path — line 78
# variable: descriptor — line 80
# variable: stream — line 81
# definition: decode — line 85
# parameter: data — line 86
# parameter: scratch — line 86
# variable: executable — line 89
# variable: scratch — line 105
# variable: directory — line 107
# variable: snapshot — line 108
# variable: completed — line 110
# variable: key — line 117
# variable: value — line 117
# definition: analyze — line 130
# parameter: args — line 130
# variable: settings — line 134
# variable: events — line 137
# variable: issues — line 138
# variable: digests — line 139
# variable: data — line 141
# variable: _ — line 144
# variable: events — line 144
# variable: issues — line 144
# variable: data — line 146
# variable: events — line 148
# variable: findings — line 149
# variable: value — line 150
# variable: connection — line 151
# variable: selected — line 167
# variable: target — line 188
# definition: main — line 197
# parameter: argv — line 197
# variable: parser — line 199
# variable: commands — line 202
# variable: demo — line 203
# variable: analysis — line 207
# variable: args — line 227
# variable: case — line 231
# END CODE MAP

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from ndal.detect import detect, policy
from ndal.inputs import read_source
from ndal.model import MAX_INPUT, Event, Issue, logs, native, unique_object
from ndal.query import query
from ndal.report import document, render
from ndal.store import database, search
from ndal.synthetic import CASES, log_sample, scenario

ROOT = Path(__file__).resolve().parents[1]


def read(path: Path, maximum: int = MAX_INPUT) -> bytes:
    """Read a same-descriptor bounded ordinary file; reject link/device/FIFO swaps before opening can block."""
    return read_source(path, maximum)


def write(path: Path, data: bytes) -> None:
    """Create a new output only (no symlink following or overwrite), owner-only mode on POSIX."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def decode(
    data: bytes, *, scratch: Path | None = None
) -> tuple[int, list[Event], list[Issue]]:
    """Invoke only this repo's compiled native binary without a shell; deadline bounds parser jobs."""
    executable = (
        ROOT / "native/packet-decoder.exe"
        if getattr(sys, "frozen", False)
        else (
            ROOT
            / "target/release"
            / ("packet-decoder.exe" if os.name == "nt" else "packet-decoder")
        )
    )
    if not executable.is_file():
        raise ValueError(
            "build the trusted decoder with cargo build --release --locked first"
        )
    if len(data) > MAX_INPUT:
        raise ValueError("capture byte limit")
    if scratch is None:
        scratch = ROOT / "out"
        scratch.mkdir(exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
        snapshot = Path(directory) / "snapshot.pcap"
        write(snapshot, data)
        completed = subprocess.run(
            [str(executable), str(snapshot)],
            capture_output=True,
            timeout=15,
            check=False,
            env={
                key: value
                for key, value in os.environ.items()
                if key.upper() in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
            },
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    if completed.returncode:
        raise ValueError(
            "capture rejected: "
            + completed.stderr.decode("ascii", errors="replace").strip()[:100]
        )
    return native(completed.stdout.decode("ascii"))


def analyze(args: argparse.Namespace) -> None:
    """Analyze capture and/or distinct-source logs; create one private report folder or fail without overwrite."""
    if args.capture is None and args.logs is None:
        raise ValueError("provide --capture and/or --logs")
    settings = policy(
        json.loads(read(args.policy, 65536), object_pairs_hook=unique_object)
    )
    events: list[Event] = []
    issues: list[Issue] = []
    digests: dict[str, str] = {}
    if args.capture:
        data = read(args.capture)
        digests["capture"] = hashlib.sha256(data).hexdigest()
        # Decode the same private byte snapshot that was hashed, never re-open the input path.
        _, events, issues = decode(data)
    if args.logs:
        data = read(args.logs)
        digests["logs"] = hashlib.sha256(data).hexdigest()
        events += logs(data)
    findings = detect(events, issues, settings)
    value = document(events, issues, findings, settings, digests)
    connection = database(events, issues)
    try:
        args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
        if args.search is not None:
            write(
                args.output / "search.json",
                json.dumps(search(connection, args.search), indent=2).encode(),
            )
        write(
            args.output / "report.json",
            (
                json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode(),
        )
        write(args.output / "report.html", render(value).encode())
        if args.query:
            selected = query(
                events,
                issues,
                findings,
                start_ns=args.query_start_ns,
                end_ns=args.query_end_ns,
                protocol=args.query_protocol,
                rule=args.query_rule,
                severity=args.query_severity,
                cursor=args.query_cursor,
                limit=args.query_limit,
            )
            write(
                args.output / "query.json",
                json.dumps(
                    selected, sort_keys=True, indent=2, allow_nan=False
                ).encode(),
            )
            write(args.output / "query.html", render(selected).encode())
        # SQLite backup uses a new exclusive file; reports retain metadata, never packet payload.
        write(args.output / "evidence.sqlite", b"")
        with closing(sqlite3.connect(args.output / "evidence.sqlite")) as target:
            connection.backup(target)
    finally:
        connection.close()
    print(
        f"Analyzed {len(events)} events, {len(issues)} issues, {len(findings)} review findings. Created by Jason Stys."
    )


def main(argv: list[str] | None = None) -> int:
    """Dispatch demo or analysis; controlled errors do not emit tracebacks or raw input data."""
    parser = argparse.ArgumentParser(
        description="Offline Network Defense Analysis Lab by Jason Stys"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser(
        "demo", help="generate reserved-address synthetic captures, no traffic"
    )
    demo.add_argument("output", type=Path)
    analysis = commands.add_parser(
        "analyze", help="analyze bounded local files into private reports"
    )
    analysis.add_argument("--capture", type=Path)
    analysis.add_argument("--logs", type=Path)
    analysis.add_argument("--policy", type=Path, default=ROOT / "config/default.json")
    analysis.add_argument("--output", type=Path, required=True)
    analysis.add_argument("--search", help="exact IPv4/hostname evidence search")
    analysis.add_argument(
        "--query",
        action="store_true",
        help="write bounded filtered analyst evidence page",
    )
    analysis.add_argument("--query-start-ns", type=int, default=0)
    analysis.add_argument("--query-end-ns", type=int, default=2**63 - 1)
    analysis.add_argument("--query-protocol", choices=("udp", "tcp"))
    analysis.add_argument("--query-rule")
    analysis.add_argument("--query-severity", choices=("review", "coverage"))
    analysis.add_argument("--query-cursor")
    analysis.add_argument("--query-limit", type=int, default=100)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
            for case in CASES:
                write(args.output / (case + ".pcap"), scenario(case))
            write(args.output / "connections.jsonl", log_sample())
            print(
                "Created 13 synthetic captures and one log sample; no packets transmitted."
            )
        else:
            analyze(args)
    except (
        ValueError,
        OSError,
        RecursionError,
        subprocess.TimeoutExpired,
        sqlite3.Error,
    ) as error:
        print(
            f"Analysis stopped ({type(error).__name__}); check input limits, build and output path. No raw input logged.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
