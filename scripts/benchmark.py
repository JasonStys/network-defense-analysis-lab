"""Jason Stys: reproducible bounded release-decoder and analysis timings; no universal performance claims."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 39
# variable: settings — line 41
# variable: result — line 42
# variable: packet — line 55
# variable: count — line 58
# variable: data — line 59
# variable: index — line 59
# variable: analysis_times — line 61
# variable: decode_times — line 61
# variable: _ — line 62
# variable: start — line 63
# variable: events — line 64
# variable: issues — line 64
# variable: observed — line 64
# variable: start — line 67
# variable: connection — line 69
# variable: median — line 75
# variable: output — line 87
# END CODE MAP

import json
import platform
import statistics
import sys
import time
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ndal.cli import ROOT, decode
from ndal.detect import detect, policy
from ndal.store import database
from ndal.synthetic import frame, pcap


def main() -> None:
    """Measure 1k/5k/20k synthetic datagrams, seven repeats after warmup; assert actual decoded counts."""
    settings = policy(json.loads((ROOT / "config/default.json").read_text()))
    result = {
        "measured_at_utc": datetime.now(UTC).isoformat(),
        "architecture": platform.machine(),
        "schema": "ndal-benchmark-v1",
        "author": "Jason Stys",
        "os": platform.system(),
        "python": platform.python_version(),
        "rust": "1.98.1",
        "repeats": 7,
        "warmups": 1,
        "scope": "Release Rust process startup + bounded temporary file IO + parse + TSV emission + Python normalization; analysis timing adds rules and in-memory SQLite. No generation time, coverage, tracemalloc or network included. Shared-runner timings are observations, not pass/fail throughput targets.",
        "workloads": [],
    }
    packet = frame(
        src="192.0.2.30", dst="192.0.2.31", dport=2001, payload=b"synthetic telemetry"
    )
    for count in [1000, 5000, 20000]:
        data = pcap([(index * 1_000_000_000, packet) for index in range(count)])
        decode(data)
        decode_times, analysis_times = [], []
        for _ in range(7):
            start = time.perf_counter()
            observed, events, issues = decode(data)
            decode_times.append(time.perf_counter() - start)
            assert observed == count and len(events) == count and not issues
            start = time.perf_counter()
            assert not detect(events, issues, settings)
            with closing(database(events, issues)) as connection:
                assert (
                    connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    == count
                )
            analysis_times.append(time.perf_counter() - start)
        median = statistics.median(decode_times)
        result["workloads"].append(
            {
                "packets": count,
                "capture_bytes": len(data),
                "decode_seconds": decode_times,
                "analysis_seconds": analysis_times,
                "decode_median_seconds": median,
                "analysis_median_seconds": statistics.median(analysis_times),
                "packets_per_second_observed": count / median,
            }
        )
    output = ROOT / "out/benchmark.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
