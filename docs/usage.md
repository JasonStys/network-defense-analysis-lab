# Setup, analyst workflow and help

Created by Jason Stys. Contact via [GitHub](https://github.com/JasonStys) or [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/).

## Installation

Install Python from python.org and rustup from rust-lang.org using their official instructions. The toolchain file pins Rust 1.98.1, which is deliberately not a floating latest version. Windows needs Visual Studio C++ build tools for the MSVC linker. This project does not install a capture driver, daemon, browser extension or security-agent hook.

Clone this repository, change to its root, run cargo build --release --locked. Python's application modules use only the standard library. An optional development environment is created with python -m venv .venv; activate it using the normal command for your shell, then install the hash-locked requirements. Do not disable PowerShell execution policy to run the app; python -m ndal.cli works without activation.

## Guided demo

~~~text
python -m ndal.cli demo out/demo
python -m ndal.cli analyze --capture out/demo/dns_burst.pcap --output out/dns-review --search 192.0.2.10
python -m ndal.cli analyze --capture out/demo/industrial_telemetry.pcap --output out/plant-review
python -m ndal.cli analyze --logs out/demo/connections.jsonl --output out/log-review
~~~

Open the new report.html in your browser; browser Find locates a rule, address or evidence ID. report.json supplies structured integration output; evidence.sqlite has metadata and issues. Exact --search writes search.json. HTML is intentionally an inert offline report, **not a hosted website or interactive dashboard**. No accounts, advertising, tracking or executable report content.

Look at the policy, input digests, capture-quality issues and evidence IDs before considering findings. Compare approved health checks or inventory jobs against the measured pattern. The report offers alternatives, not a hiring/compliance/security decision. Escalation, incident handling or blocking remains an authorized human's responsibility.

## Scenario intent

| Case | Intent / expected rules |
| --- | --- |
| office_baseline | Catalog DNS lookup and one HTTPS SYN; none |
| industrial_telemetry | 30 synthetic device UDP measurements, no payload exported; none |
| dns_burst | One client receives ten stale-name NXDOMAINs; DNS burst |
| dns_long_label | High-entropy synthetic identifier under .example; long label |
| port_fanout | Ten distinct synthetic target ports; fan-out |
| periodic_connections | Ten evenly spaced synthetic initiations; periodicity |
| mixed_hosts | Ten clients receive one failure each; none |
| sparse_failures | Failures separated by 61 seconds; none |
| syn_ack_only | Responses must not count as initiations; none |
| malformed_dns | Valid transport, invalid DNS body; capture quality |
| truncated_packet | Snapshot/original length mismatch; capture quality |
| ipv6_unsupported | Coverage issue, not silently clean IPv6 |
| reordered | Explicit ordering issues; rules use sorted event times |

Use only synthetic or explicitly authorized copies of data. This repo's tests/demo use RFC documentation addresses and reserved .example names; nothing is transmitted. A PCAP may contain private payloads even when the report exports only metadata. Do not commit source captures, reports or databases containing real traffic.

## Configuration

Copy config/default.json to a local ignored directory and pass --policy PATH. Change only documented bounded fields. Example connection exception:

~~~json
{"src":"192.0.2.10","dst":"198.51.100.20","dport":443,"reason":"Approved synthetic health checks"}
~~~

Add to allowed_connections, not as an extra top-level key. DNS exception:

~~~json
{"name":"known-identifier.example","reason":"Approved synthetic telemetry name"}
~~~

Add to allowed_domains. Preserve all other fields. Reports record thresholds and exceptions. Raising thresholds reduces review noise but may miss suspicious patterns; lowering them may increase false positives. There is no automatic parameter optimization or external threat-intelligence lookup.

## Troubleshooting and privacy

Exit 2 is a controlled input/build/output/deadline failure. Check the supported contracts, compile the trusted release decoder, and choose a fresh writable output directory. A directory, unknown capture format or >8 MiB source is rejected. Existing report folders are never overwritten; retain or remove them yourself. A failed write can leave a partial **new** output folder; do not assume it is a complete review.

Run python -m ndal.cli --help or the subcommand's --help. Scanner/dependency downloads need internet only during setup/CI. tcpdump is optional locally and required for CI's independent conformance test; scripts/differential.py always uses -r, never a live interface. Linux/macOS/Windows assurance runs are recorded in CI.

POSIX creates owner-only output files/directories. Windows relies on inherited NTFS permissions; keep outputs in your private user profile and check ACLs before sensitive use. These files are not encrypted, and OS administrators can access them. Hashes establish byte identity, not authenticated custody.
