# Parser, evidence and detection contracts

Author: Jason Stys. This document is the supported subset, not a claim of complete protocol validation.

## Bounded inputs

| Boundary | Hard limit / behavior |
| --- | --- |
| PCAP source / JSONL source | 8 MiB each, regular local files only |
| Capture records | 20,000; fatal error if exceeded, no partial success |
| Snapshot / captured packet | 1–65,535-byte snapshot; captured length ≤ snapshot and original |
| Timestamp | u32 seconds; fraction < 1 million or 1 billion; normalized integer nanoseconds |
| DNS | One IN-class question, standard opcode; ASCII hostname subset; expanded wire name ≤255, label ≤63, ≤128 pointer/name steps, ≤128 resource records |
| JSONL | 20,000 objects, ≤4,096 characters per line, exact Event fields, unique log- IDs |
| Native TSV | Version 1, ≤12 MiB / 60,001 lines; every packet accounted for by event or issue |
| Combined analysis | ≤40,000 events and ≤40,000 issues; distinct sources only |
| Policy | 64 KiB; all exact fields required; finite bounded numbers; ≤100 exceptions per list |
| Evidence per finding | First 100 IDs plus total count; full bounded event metadata remains in JSON/SQL |
| SQL search | Exact source/destination/hostname; 1–1,000 results, value ≤253 chars |
| Native job | 15-second deadline through Python; no shell evaluation |

Both classic PCAP 2.4 byte orders and micro/nanosecond magic variants are supported. Reserved legacy global fields are ignored as specified. Only linktype 1 with no additional FCS flags is supported. Container header, record length and timestamp errors are fatal. A short final record cannot make an earlier valid packet look like a fully validated capture.

Ethernet IPv4 and UDP/TCP envelope lengths and Internet checksums are checked. UDP zero checksum is legal in this IPv4-only subset. IPv4 options and TCP options are not interpreted; validated header lengths skip them. Ethernet padding may follow the IP datagram and is not treated as application payload. DNS record owner names/envelopes are validated, but RDATA contents, DNSSEC semantics, transaction/answer correlation and response authenticity are not interpreted. DNS TC-bit messages are explicitly incomplete and excluded from DNS detections.

Backward DNS compression pointers must target ≥12 and <current position. Bounds, expanded length and hop cap prevent cycles/forward pointers from exhausting resources. Hostname restrictions intentionally reject valid binary DNS labels and non-ASCII names; encoded international names must be ASCII punycode. Root questions are an empty name, distinct from absent DNS. Unsupported question/opcode/class or record bounds are visible issues, not clean DNS results.

## Explicit omissions

PCAPNG, raw IP linktypes, VLAN, IPv6, ARP and other EtherTypes, fragmented IPv4, other transport protocols, DNS-over-TCP, encrypted DNS/TLS, TCP reassembly, FCS verification, retransmission deduplication and full protocol semantics are not implemented. Unsupported linktype/container formats are fatal; unsupported packet protocols are coverage issues. Checksum offloading can cause false corruption findings in real captures. Only synthetic fixtures were accepted for this portfolio; no claim of validation against a production traffic corpus.

## Native TSV / logs

Header: NDAL, version 1, packet count, separated by TAB. O rows have packet ID, time_ns, src, dst, sport, dport, protocol, flags, IP bytes, DNS name/response/rcode/qtype. Absent DNS uses four "-" sentinels; a root name is empty. I rows have packet ID and an allowlisted issue code. Safe ASCII names cannot inject delimiters.

JSONL fields exactly match Event: identifier, time_ns, src, dst, sport, dport, protocol, flags, bytes, name, response, rcode, qtype. DNS absent uses four nulls. IPv4 strings must be canonical; UDP flags zero; DNS fields require UDP port 53 and a boolean response. Integer booleans, arbitrary coercion, duplicate JSON keys and duplicate IDs are rejected. The generator emits a working example. The pipeline never executes input as code or SQL.

## Detection semantics

- NXDOMAIN: count rcode=3 responses per **destination client**, not resolver source; maximum inclusive window, default 8 in 60 seconds.
- Long label: query only; longest label length ≥40 and empirical character entropy ≥4.2 bits/character.
- TCP fan-out: SYN=1, ACK=0; per source/destination pair, maximum inclusive 60-second window, ≥8 distinct destination ports.
- Periodicity: same source/destination/port SYN initiations, ≥6 observations, mean spacing ≥1 second, population coefficient of variation ≤0.05. This uses the **whole bounded series**, not a sliding-window detector.
- Capture quality: every error/limitation code, bounded packet IDs and total count; unsupported_* gets coverage severity, other issues review. No severity is an attack-confidence probability.

Events are sorted by time and ID before windows. Mixed clients cannot contribute to one client's score. Maximum ties select the earliest window. Exact allowed connection triples suppress TCP pattern rules only; exact allowed DNS names suppress DNS rules only. Every exception needs a 5–200-character reason. There are no wildcard exceptions. Suppressions and thresholds are copied into the report.

Normal identifiers, scheduled jobs, approved diagnostics, health checks, resolver failures and retransmissions are alternatives; explainable review is essential. A matching pattern is not proof of compromise.
