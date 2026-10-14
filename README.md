# Network Defense Analysis Lab

[![Validate](https://github.com/JasonStys/network-defense-analysis-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonStys/network-defense-analysis-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/JasonStys/network-defense-analysis-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/JasonStys/network-defense-analysis-lab/actions/workflows/codeql.yml)

Created by **Jason Stys** — [GitHub](https://github.com/JasonStys) · [LinkedIn/contact](https://www.linkedin.com/in/jason-stys-31b30b351/).

A defensive, offline portfolio lab that turns bounded **synthetic packet captures and normalized network logs** into explainable analyst findings, searchable SQL evidence, and inert HTML/JSON reports. It demonstrates memory-safe parsing, detection engineering, cross-language contracts, negative testing and reproducible performance measurements.

**It does not capture live traffic, scan targets, contact DNS servers, decrypt TLS, automatically block hosts or attribute attacks.** There is no hosted service, account system, cloud deployment or telemetry. Missing findings do not prove a network safe. Generated evidence stays local and ignored by Git.

## Major features

- **Rust wire decoder:** dependency-free, no unsafe code; classic PCAP endian/micro/nanosecond variants; Ethernet/IPv4/UDP/TCP metadata, Internet checksums and bounded compressed DNS question parsing. Truncation, unsupported formats and protocol envelope errors remain visible.
- **Python analysis:** per-client NXDOMAIN bursts, high-entropy long DNS labels, per-source/destination TCP port fan-out and periodic SYN initiation hypotheses. Inclusive sliding windows avoid minute-bucket blind spots; exact scoped allowlists require explanations.
- **SQL evidence:** strict SQLite schema, transactional import, indexed source/time and DNS-client/time access, parameterized exact searches and metadata-only portable snapshots.
- **Readable reports:** policy and input SHA256 provenance, measurements, bounded packet/log evidence references, false-positive alternatives; escaped, script-free HTML with a deny-by-default CSP.
- **Synthetic scenarios:** office product lookup, industrial telemetry, suspicious patterns, benign negatives, multi-client isolation, timestamp reordering and deliberately malformed captures. No real organizations, people or network traces.
- **Assurance:** debug/release native tests and deterministic mutation fuzzing; independent tcpdump/libpcap fixture comparison in CI; Python property/contract/integration tests with a 95% all-runtime-module coverage floor; formatting, strict types, secret and dependency checks.

## Run locally

Requires Python 3.12–3.14 and the pinned Rust 1.98.1 toolchain (rustup). On Windows Rust's MSVC toolchain also needs Microsoft's C++ build tools. Building needs development tools, not administrator/network-capture privileges. The Python application runtime has no pip dependencies.

Use these commands from the repository root, in PowerShell or a POSIX shell:

~~~text
cargo build --release --locked
python -m ndal.cli demo out/demo
python -m ndal.cli analyze --capture out/demo/dns_burst.pcap --logs out/demo/connections.jsonl --output out/review --search 192.0.2.10
~~~

Open the generated report.html locally in a browser. This example produces two review hypotheses, one DNS burst and one periodic log connection pattern. Each output directory must be new; the application refuses to overwrite an earlier review. These are different synthetic event sources; do not merge equivalent capture/log copies or counts will be duplicated.

For setup, configuration, log format, troubleshooting and analyst workflow, see [usage](docs/usage.md). For explicit supported limits and omissions, see [contracts](docs/contracts.md). [Validation evidence](docs/reports/validation.md) distinguishes local results from CI.

## Validate

Create and activate a Python virtual environment, then:

~~~text
python -m pip install --require-hashes -r requirements-dev.lock
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --release --locked
cargo build --release --locked
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest --cov=ndal --cov-report=term-missing:skip-covered
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/validate_repo.py
python scripts/benchmark.py
~~~

CI also runs the entire locked development dependency audit, pinned Gitleaks/actionlint and supported Python CodeQL security-extended analysis. Linux conformance uses the official Ubuntu tcpdump package against **files**, never interfaces. Compiler/package/scanner installation needs network access; normal analysis does not. CI uploads no artifacts or CodeQL databases and uses no Actions caches.

## Design and navigation

~10 lines of commands are enough to demonstrate the pipeline; there is deliberately no UI framework, server or capture driver. Read the [architecture decision](docs/architecture.md), [testing strategy](docs/testing.md), [threat model/security policy](docs/security.md), [performance methodology](docs/performance.md) and [primary research](docs/research.md).

Every code file has an authored purpose plus CI-checked generated symbol/variable line locations. Python uses AST parsing; Rust/SQL/workflow maps are lexical declaration indexes, independently checked by native compilers/tests or actionlint—not advertised as AST semantic analysis. Descriptive names and per-function/class doc comments document contracts without duplicating every expression in prose.

## Complete file guide

Generated from the exact tracked inventory; unknown files or stale summaries fail validation. Generated private evidence is excluded.

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform bounded native/evidence assurance; no uploaded artifacts or Actions caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: supported Python security-extended analysis; no CodeQL database artifact upload. |
| [.gitignore](.gitignore) | Exclude private captures, evidence, local environments and generated builds. |
| [Cargo.lock](Cargo.lock) | Complete dependency-free native package graph, checked with --locked. |
| [Cargo.toml](Cargo.toml) | Jason Stys: dependency-free bounded offline packet decoder and native mutation tests. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | Network Defense Analysis Lab. |
| [config/default.json](config/default.json) | Strict tunable detection thresholds with empty explicitly scoped allowlists. |
| [docs/architecture.md](docs/architecture.md) | Architecture and ADR-001: bounded offline evidence. |
| [docs/contracts.md](docs/contracts.md) | Parser, evidence and detection contracts. |
| [docs/performance.md](docs/performance.md) | Complexity and benchmark methodology. |
| [docs/release.md](docs/release.md) | Release and maintenance checklist. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured synthetic Windows benchmark snapshot, not a throughput promise. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source CI job snapshot, not a future guarantee. |
| [docs/reports/validation.md](docs/reports/validation.md) | Validation and accepted-source evidence. |
| [docs/research.md](docs/research.md) | Primary research and implementation rationale. |
| [docs/security.md](docs/security.md) | Threat model and security policy. |
| [docs/testing.md](docs/testing.md) | Testing strategy and acceptance gates. |
| [docs/usage.md](docs/usage.md) | Setup, analyst workflow and help. |
| [native/lib.rs](native/lib.rs) | Jason Stys: bounded classic-PCAP/Ethernet/IPv4/UDP/TCP/DNS metadata decoder. |
| [native/main.rs](native/main.rs) | Jason Stys: read one bounded regular capture file and emit safe versioned TSV metadata. |
| [native/tests.rs](native/tests.rs) | Jason Stys: independent native wire fixtures, boundary tests and deterministic mutation fuzzing. |
| [ndal/\_\_init\_\_.py](ndal/__init__.py) | Jason Stys: offline synthetic network evidence analysis, no runtime third-party packages. |
| [ndal/cli.py](ndal/cli.py) | Jason Stys: local bounded file analysis, synthetic demo generation and private no-overwrite evidence output. |
| [ndal/detect.py](ndal/detect.py) | Jason Stys: bounded explainable DNS/window/fan-out/periodicity hypotheses with scoped allowlists. |
| [ndal/model.py](ndal/model.py) | Jason Stys: strict immutable metadata models and native TSV/network-log trust boundaries. |
| [ndal/report.py](ndal/report.py) | Jason Stys: deterministic machine-readable and escaped inert HTML analyst reports, no active content. |
| [ndal/store.py](ndal/store.py) | Jason Stys: transactional metadata-only SQLite evidence store and parameterized search. |
| [ndal/synthetic.py](ndal/synthetic.py) | Jason Stys: deterministic synthetic wire/log fixtures with reserved addresses; never sends traffic. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict Python tooling and all-runtime-module branch/statement coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: exact development-only tools; Python runtime uses only the standard library. |
| [requirements-dev.lock](requirements-dev.lock) | Full universal hash-locked Python development dependency graph. |
| [rust-toolchain.toml](rust-toolchain.toml) | Jason Stys: reproducible tested compiler; no automatic floating stable toolchain. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: reproducible bounded release-decoder and analysis timings; no universal performance claims. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: generate exact definition/variable line maps and verify Python function/class contracts. |
| [scripts/differential.py](scripts/differential.py) | Jason Stys: independent libpcap/tcpdump fixture conformance, synthetic files only and no live interfaces. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: private-evidence exclusion, exact links/pins and dependency-free/offline runtime gates. |
| [sql/schema.sql](sql/schema.sql) | Jason Stys: strict transactional metadata-only evidence schema with indexed human-review searches. |
| [sql/search.sql](sql/search.sql) | Jason Stys: exact source/hostname search uses bound values, never interpolated SQL or wildcard guesses. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: fail-closed wire/log/policy contracts, boundary semantics and bounded evidence property tests. |
| [tests/test\_pipeline.py](tests/test_pipeline.py) | Jason Stys: real Rust subprocess, labeled scenario, CLI privacy, evidence SQL and report integration tests. |
| [tools.lock.json](tools.lock.json) | Official scanner versions, release URLs and pinned SHA256 digests. |

<!-- END FILE GUIDE -->

MIT licensed. Educational assurance is not a certification, production IDS, compliance attestation or substitute for an authorized security assessment.
