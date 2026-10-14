"""Jason Stys: local bounded file analysis, synthetic demo generation and private no-overwrite evidence output."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 65
# definition: read — line 68
# parameter: maximum — line 68
# parameter: path — line 68
# variable: stream — line 72
# variable: data — line 73
# definition: write — line 79
# parameter: data — line 79
# parameter: path — line 79
# variable: descriptor — line 81
# variable: stream — line 82
# definition: decode — line 86
# parameter: data — line 86
# variable: executable — line 88
# variable: directory — line 100
# variable: snapshot — line 101
# variable: completed — line 103
# definition: analyze — line 117
# parameter: args — line 117
# variable: settings — line 121
# variable: events — line 124
# variable: issues — line 125
# variable: digests — line 126
# variable: data — line 128
# variable: _ — line 131
# variable: events — line 131
# variable: issues — line 131
# variable: data — line 133
# variable: events — line 135
# variable: findings — line 136
# variable: value — line 137
# variable: connection — line 138
# variable: target — line 155
# definition: main — line 164
# parameter: argv — line 164
# variable: parser — line 166
# variable: commands — line 169
# variable: demo — line 170
# variable: analysis — line 174
# variable: args — line 182
# variable: case — line 186
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
from ndal.model import MAX_INPUT, Event, Issue, logs, native, unique_object
from ndal.report import document, render
from ndal.store import database, search
from ndal.synthetic import CASES, log_sample, scenario

ROOT = Path(__file__).resolve().parents[1]


def read(path: Path, maximum: int = MAX_INPUT) -> bytes:
    """Read one explicit regular file with size plus bounded-read checks, not devices/directories."""
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("input file/byte limit")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("input changed/exceeds byte limit")
    return data


def write(path: Path, data: bytes) -> None:
    """Create a new output only (no symlink following or overwrite), owner-only mode on POSIX."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def decode(data: bytes) -> tuple[int, list[Event], list[Issue]]:
    """Invoke only this repo's compiled native binary without a shell; deadline bounds parser jobs."""
    executable = (
        ROOT
        / "target/release"
        / ("packet-decoder.exe" if os.name == "nt" else "packet-decoder")
    )
    if not executable.is_file():
        raise ValueError(
            "build the trusted decoder with cargo build --release --locked first"
        )
    if len(data) > MAX_INPUT:
        raise ValueError("capture byte limit")
    (ROOT / "out").mkdir(exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=ROOT / "out") as directory:
        snapshot = Path(directory) / "snapshot.pcap"
        write(snapshot, data)
        completed = subprocess.run(
            [str(executable), str(snapshot)],
            capture_output=True,
            timeout=15,
            check=False,
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
    except (ValueError, OSError, RecursionError, subprocess.TimeoutExpired) as error:
        print(
            f"Analysis stopped ({type(error).__name__}); check input limits, build and output path. No raw input logged.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
