# Testing strategy and acceptance gates

Author: Jason Stys. Tests exercise actual native execution and database behavior, not a mocked success summary.

## Coverage by layer

Native tests independently build wire packets and validate all four PCAP formats, DNS answer compression, root names, incomplete DNS, every seed prefix, pointer/name/record caps, checksum corruption, IPv4 lengths/fragments/reserved flag, UDP/TCP envelopes, explicit unsupported DNS TCP, zero-length packet count exhaustion, reordered time and fatal-after-valid-record behavior.

Deterministic native mutation fuzzing runs 100,000 fixed-seed mutations, truncations and appends against both actual PCAP and DNS functions in each debug/release suite. It is **not** coverage-guided libFuzzer/AFL, a full corpus campaign or a proof of parser correctness. Hypothesis adds 200 reproducible bounded arbitrary-byte JSONL cases.

Python tests invoke the repository-built native executable and compare all 13 labeled scenario rule sets. They verify exact allowlist scope, client isolation, inclusive cross-minute windows, repeated-port eviction, earliest ties, irregular/too-fast/too-short periodicity negatives, 100-ID evidence caps, SQL injection/constraints/duplicate rollback, no-overwrite/private output, source hashing, controlled missing-build/deadline/input errors, inert escaped reports and strict schemas.

CI's independent tcpdump/libpcap test compares packet counts and IPv4 endpoints/ports on seven valid scenarios plus all four PCAP formats. It does **not** validate every DNS semantic, compare arbitrary malformed-input interpretations or inspect live interfaces. The official distro tcpdump version is printed in job logs; only the app compiler/development graph is pinned. Deliberately malformed fixtures are not required to agree with a permissive decoder.

## Required gates

- Rust format, clippy warnings denied, debug and release native suites; release overflow checks enabled.
- Strict Python types and Ruff checks, all runtime modules in coverage with ≥95% combined statements/branches; no omitted module or skipped known defect.
- Full hash-locked Python development graph audit; Rust has zero third-party dependencies, verified by Cargo.lock inspection.
- Full-history Gitleaks, actionlint, privacy/offline/link inventories and exact code/file map drift checks.
- Linux Python 3.12/3.14, Windows 3.14, macOS 3.14 integration suites; separate Linux conformance/benchmark job.
- Python CodeQL security-extended analysis. Rust clippy/native tests are separate; no unsupported Rust CodeQL coverage is claimed.

Every gate must pass on final main. Failed first attempts remain in GitHub history and are not relabeled successful. Immutable report snapshots identify the source commit accepted, instead of referring to a future self-referential commit. Timing values are measured evidence, not brittle shared-runner throughput thresholds. See [performance](performance.md) and [validation](reports/validation.md).
