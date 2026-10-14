# Architecture and ADR-001: bounded offline evidence

Status: accepted. Author: Jason Stys. Scope: standalone defensive portfolio lab, not a network sensor.

## Responsibilities and trust boundaries

| Stage | Language | Input / output | Authority |
| --- | --- | --- | --- |
| Wire parsing | Rust | Bounded local PCAP → versioned TSV metadata + issues | No network, no payload export, no unsafe code |
| Normalization | Python | Checked TSV / exact-schema JSONL → immutable events | Reject unknown fields, duplicate IDs/keys, invalid ranges |
| Detection | Python | Event-time sorted metadata + explicit policy → hypotheses | Explain measured patterns; never blocking/attribution |
| Storage | SQL / Python sqlite3 | One transaction → strict in-memory DB + local backup | Parameterized search; no arbitrary user SQL |
| Reporting | Python / HTML | Metadata, policy, SHA256 → JSON + inert HTML | No scripts, frames, resources, forms or telemetry |

The CLI reads a bounded source once, hashes those bytes, copies that exact snapshot into a temporary private directory and asks the trusted repository-built decoder to read it. The source is not reopened for decoding. Fatal container errors discard all intermediate parsed results; packet-specific defects/limitations remain reportable. Cleanup of owned temporary snapshots is automatic, not deletion of user inputs.

## Decision and trade-offs

Use a small dependency-free Rust parser to make length checks, memory safety, error classification and performance auditable in a portfolio. Python's standard library suits orchestration, strict contracts, statistics and synthetic fixture generation. SQLite supplies real transactions, constraints and query indexes without a service to install.

The libpcap maintainers recommend libpcap rather than custom format readers to benefit from evolving format support. This lab intentionally demonstrates a narrow handwritten parser, **not** a production replacement. Independent libpcap/tcpdump CI checks help detect shared generator/parser mistakes. A production sensor should use maintained protocol libraries, sandboxed worker isolation and a much larger real-world authorized corpus.

Avoid a live sensor, SIEM service, web backend, heavy frontend, containers and external threat-intelligence APIs. They expand authority, privacy exposure and dependency complexity without serving this particular evidence exercise. A downloadable source build plus local HTML report is sufficient.

No custom cryptography: SHA256 is standard-library provenance hashing, not authentication or signing. Internet checksums detect corruption and are not cryptographic integrity. A malicious actor can alter an entire evidence set and regenerate its hashes; custody must be handled outside this lab.

## Modularity and extension

Change reviewed numeric thresholds in config/default.json or pass a separate policy. Use a distinct future adapter to map a known log schema into Event; do not guess the meaning of arbitrary log formats. Add a native protocol only with a documented bounded contract, positive/negative wire fixtures, issue classification and differential tests. Keep unsupported protocols visible.

Future PCAPNG, IPv6, VLAN and reassembly support are separate design decisions. They are **not implemented** here. The full symbol/file inventories identify extension points; shallow ndal/native/sql/scripts/tests/docs directories keep paths short.
