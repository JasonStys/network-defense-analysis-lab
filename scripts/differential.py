"""Jason Stys: independent libpcap/tcpdump fixture conformance, synthetic files only and no live interfaces."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: compare — line 31
# parameter: data — line 31
# variable: directory — line 34
# variable: path — line 35
# variable: completed — line 37
# variable: count — line 43
# variable: events — line 43
# variable: issues — line 43
# variable: lines — line 44
# variable: line — line 46
# variable: value — line 46
# definition: main — line 50
# variable: version — line 52
# variable: case — line 56
# variable: little — line 66
# variable: nano — line 67
# END CODE MAP

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ndal.cli import ROOT, decode, write
from ndal.synthetic import frame, pcap, scenario


def compare(data: bytes) -> None:
    """Compare native IPv4/TCP/UDP metadata count to tcpdump reading the same private fixture."""
    ROOT.joinpath("out").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "out") as directory:
        path = Path(directory) / "synthetic.pcap"
        write(path, data)
        completed = subprocess.run(
            ["tcpdump", "-n", "-q", "-tt", "-r", str(path), "tcp or udp"],
            capture_output=True,
            timeout=15,
            check=True,
        )
        count, events, issues = decode(data)
        lines = completed.stdout.decode("ascii").splitlines()
        assert not issues and count == len(events) == len(lines)
        for value, line in zip(events, lines, strict=True):
            assert f"{value.src}.{value.sport} > {value.dst}.{value.dport}" in line


def main() -> None:
    """Check seven meaningful fixtures plus all endian/time variants; tcpdump version stays in CI logs."""
    version = subprocess.run(
        ["tcpdump", "--version"], capture_output=True, timeout=15, check=True
    )
    print(version.stdout.decode("ascii").splitlines()[0])
    for case in [
        "office_baseline",
        "industrial_telemetry",
        "dns_burst",
        "dns_long_label",
        "port_fanout",
        "periodic_connections",
        "syn_ack_only",
    ]:
        compare(scenario(case))
    for little in [True, False]:
        for nano in [True, False]:
            compare(pcap([(1_234_567_000, frame(dport=2001))], little, nano))
    print(
        "11 independent libpcap/tcpdump conformance fixtures passed; no traffic captured or sent."
    )


if __name__ == "__main__":
    main()
