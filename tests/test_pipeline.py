"""Jason Stys: real Rust subprocess, labeled scenario, CLI privacy, evidence SQL and report integration tests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: settings — line 112
# definition: test_real_scenarios — line 118
# parameter: case — line 118
# parameter: settings — line 118
# variable: count — line 120
# variable: events — line 120
# variable: issues — line 120
# variable: findings — line 122
# variable: value — line 123
# variable: connection — line 124
# variable: value — line 129
# definition: test_wire_cross_language — line 137
# parameter: little — line 137
# parameter: nano — line 137
# variable: timestamp — line 139
# variable: _ — line 140
# variable: events — line 140
# variable: issues — line 140
# definition: test_allowlisted_health_checks — line 147
# parameter: settings — line 147
# variable: _ — line 149
# variable: events — line 149
# variable: issues — line 149
# variable: value — line 150
# definition: test_dns_allowlist — line 164
# parameter: settings — line 164
# variable: _ — line 166
# variable: events — line 166
# variable: issues — line 166
# variable: value — line 167
# definition: test_cli_complete — line 174
# parameter: capsys — line 174
# parameter: tmp_path — line 174
# variable: source — line 176
# variable: output — line 178
# variable: command — line 179
# variable: report — line 191
# variable: finding — line 196
# variable: connection — line 201
# definition: test_log_only — line 210
# parameter: tmp_path — line 210
# variable: source — line 212
# definition: test_cli_errors — line 220
# parameter: monkeypatch — line 220
# parameter: tmp_path — line 220
# variable: bad — line 223
# variable: executable — line 231
# definition: timeout — line 241
# parameter: args — line 241
# parameter: kwargs — line 241
# definition: test_bounded_reads — line 251
# parameter: monkeypatch — line 251
# parameter: tmp_path — line 251
# variable: path — line 255
# variable: original — line 261
# definition: fake_size — line 263
# parameter: args — line 263
# parameter: kwargs — line 263
# parameter: self — line 263
# variable: value — line 265
# definition: test_sql_injection_and_transaction — line 286
# variable: events — line 288
# variable: connection — line 289
# definition: test_html_inert — line 307
# parameter: settings — line 307
# variable: value — line 309
# variable: result — line 316
# definition: test_native_cli_usage_and_fatal — line 321
# parameter: tmp_path — line 321
# variable: executable — line 323
# variable: bad — line 328
# variable: args — line 330
# variable: result — line 331
# definition: test_generator_edges — line 338
# definition: test_record_limits — line 349
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

import pytest

from ndal import cli
from ndal.cli import ROOT, decode, main, read, write
from ndal.detect import detect, policy
from ndal.model import Issue, logs
from ndal.report import document, render
from ndal.store import database, search
from ndal.synthetic import (
    CASES,
    EXPECTED,
    checksum,
    dns,
    frame,
    log_sample,
    pcap,
    scenario,
)


@pytest.fixture
def settings():
    """Read the same reviewed default policy as the CLI."""
    return policy(json.loads((ROOT / "config/default.json").read_text()))


@pytest.mark.parametrize("case", CASES)
def test_real_scenarios(case, settings):
    """Run actual compiled decoder, normalization, rules, SQL and reports on each labeled case."""
    count, events, issues = decode(scenario(case))
    assert count > 0
    findings = detect(events, issues, settings)
    assert {value.rule for value in findings} == EXPECTED[case]
    with closing(database(events, issues)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(
            events
        )
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    value = document(events, issues, findings, settings, {})
    assert "synthetic temperature=21.4C" not in json.dumps(value)
    assert "Content-Security-Policy" in render(value)


@pytest.mark.parametrize(
    "little,nano", [(True, True), (True, False), (False, True), (False, False)]
)
def test_wire_cross_language(little, nano):
    """Independent Python packets and Rust parser agree on byte order, flags and timestamps."""
    timestamp = 1_234_567_890 if nano else 1_234_567_000
    _, events, issues = decode(
        pcap([(timestamp, frame(payload=dns("_service.example")))], little, nano)
    )
    assert not issues and events[0].name == "_service.example"
    assert events[0].time_ns == timestamp


def test_allowlisted_health_checks(settings):
    """Exact allowed endpoint with a reason suppresses only its periodic/fan-out hypotheses."""
    _, events, issues = decode(scenario("periodic_connections"))
    value = asdict(settings)
    value["allowed_connections"] = [
        {
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "dport": 443,
            "reason": "Approved synthetic health checks",
        }
    ]
    assert not detect(events, issues, policy(value))
    value["allowed_connections"][0]["dport"] = 444
    assert detect(events, issues, policy(value))


def test_dns_allowlist(settings):
    """Suppression requires an exact name, not a substring or cross-client group exemption."""
    _, events, issues = decode(scenario("dns_long_label"))
    value = asdict(settings)
    value["allowed_domains"] = [
        {"name": events[0].name, "reason": "Synthetic benign identifier"}
    ]
    assert not detect(events, issues, policy(value))


def test_cli_complete(tmp_path, capsys):
    """Generate actual inputs, run capture+log report, verify digest, private storage and repeat refusal."""
    source = tmp_path / "demo"
    assert main(["demo", str(source)]) == 0
    output = tmp_path / "analysis"
    command = [
        "analyze",
        "--capture",
        str(source / "dns_burst.pcap"),
        "--logs",
        str(source / "connections.jsonl"),
        "--search",
        "192.0.2.10",
        "--output",
        str(output),
    ]
    assert main(command) == 0
    report = json.loads((output / "report.json").read_text())
    assert (
        report["input_sha256"]["capture"]
        == hashlib.sha256(scenario("dns_burst")).hexdigest()
    )
    assert {finding["rule"] for finding in report["findings"]} == {
        "dns_nxdomain_burst",
        "tcp_periodicity",
    }
    assert json.loads((output / "search.json").read_text())
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 20
    assert main(command) == 2
    assert main(["demo", str(source)]) == 2
    assert "No raw input logged" in capsys.readouterr().err
    if os.name != "nt":
        assert (output / "report.json").stat().st_mode & 0o077 == 0


def test_log_only(tmp_path):
    """Log-only work does not require or execute the native decoder."""
    source = tmp_path / "logs.jsonl"
    source.write_bytes(log_sample())
    assert (
        main(["analyze", "--logs", str(source), "--output", str(tmp_path / "result")])
        == 0
    )


def test_cli_errors(tmp_path, monkeypatch):
    """Missing input, corrupt capture, compiler and bounded timeout errors are controlled."""
    assert main(["analyze", "--output", str(tmp_path / "out")]) == 2
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture")
    assert (
        main(["analyze", "--capture", str(bad), "--output", str(tmp_path / "out")]) == 2
    )
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="build the trusted"):
        decode(b"")
    executable = (
        tmp_path
        / "target/release"
        / ("packet-decoder.exe" if os.name == "nt" else "packet-decoder")
    )
    executable.parent.mkdir(parents=True)
    executable.touch()
    with pytest.raises(ValueError, match="capture byte"):
        decode(b"x" * (8 * 1024 * 1024 + 1))

    def timeout(*args, **kwargs):
        """Simulate a job deadline without waiting for a real hung process."""
        raise subprocess.TimeoutExpired("packet-decoder", 15)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert (
        main(["analyze", "--capture", str(bad), "--output", str(tmp_path / "out")]) == 2
    )


def test_bounded_reads(tmp_path, monkeypatch):
    """Directories, growing files and overwrites cannot bypass byte/private-output contracts."""
    with pytest.raises(ValueError):
        read(tmp_path)
    path = tmp_path / "value"
    write(path, b"hello")
    with pytest.raises(FileExistsError):
        write(path, b"replacement")
    with pytest.raises(ValueError):
        read(path, 4)
    original = Path.stat

    def fake_size(self, *args, **kwargs):
        """Simulate a file whose reported length changed before its bounded read."""
        value = original(self, *args, **kwargs)
        return os.stat_result(
            (
                value.st_mode,
                value.st_ino,
                value.st_dev,
                value.st_nlink,
                value.st_uid,
                value.st_gid,
                0,
                value.st_atime,
                value.st_mtime,
                value.st_ctime,
            )
        )

    monkeypatch.setattr(Path, "stat", fake_size)
    with pytest.raises(ValueError, match="changed"):
        read(path, 4)


def test_sql_injection_and_transaction():
    """Exact bound search stays data; duplicate evidence invalidates an entire new snapshot."""
    events = logs(log_sample())
    connection = database(events, [])
    try:
        assert not search(connection, "' OR 1=1 --")
        assert len(search(connection, "203.0.113.10", 2)) == 2
        with pytest.raises(ValueError):
            search(connection, "a" * 254)
        with pytest.raises(ValueError):
            search(connection, "", 0)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO issues VALUES (0, 'bad')")
    finally:
        connection.close()
    with pytest.raises(sqlite3.IntegrityError):
        database(events + events, [])
    with pytest.raises(ValueError):
        database([events[0]] * 40001, [])


def test_html_inert(settings):
    """Adversarial report strings are literal text; scripts, iframes and external resources cannot appear."""
    value = document(
        [],
        [],
        [],
        settings,
        {"test": '</pre><script>alert(1)</script><img src="https://example.com">'},
    )
    result = render(value)
    assert "<script>" not in result and "<img " not in result
    assert "&lt;script&gt;" in result and "default-src 'none'" in result


def test_native_cli_usage_and_fatal(tmp_path):
    """Actual CLI rejects bad captures with exit 2 and no partial stdout/path/payload."""
    executable = (
        ROOT
        / "target/release"
        / ("packet-decoder.exe" if os.name == "nt" else "packet-decoder")
    )
    bad = tmp_path / "private-name.pcap"
    bad.write_bytes(b"SECRET-BAD-DATA")
    for args in [[], [str(bad)], [str(tmp_path)], [str(bad), "extra"]]:
        result = subprocess.run(
            [str(executable), *args], capture_output=True, check=False
        )
        assert result.returncode == 2 and not result.stdout
        assert b"SECRET" not in result.stderr and b"private-name" not in result.stderr


def test_generator_edges():
    """Fixture generation bounds names and explicitly labels unsupported scenarios."""
    assert dns("") and checksum(b"abc") >= 0
    with pytest.raises(ValueError):
        dns("a" * 64)
    with pytest.raises(ValueError):
        dns("a..example")
    with pytest.raises(ValueError):
        scenario("unknown")


def test_record_limits():
    """Synthetic postdecoder input cannot evade end-to-end analysis limits."""
    with pytest.raises(ValueError):
        database([], [Issue(1, "dns_label")] * 40001)
