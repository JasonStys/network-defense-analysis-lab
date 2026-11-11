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

### Graphical Windows workbench

The native workbench runs the real Rust/Python/SQLite pipeline with editable
authorized PCAP/log/policy controls, exact searches, stable evidence pages and
durable owner-local history. Its prepared fictional scenarios are inputs inside
this same application. The portable build includes its runtime and needs no user
compiler or command setup. Read the [native workflow, privacy and build guide](docs/native-workbench.md).
The current source recipe and actual packaged acceptance are recorded separately
from publication in the [native validation report](docs/reports/native-workbench-2026-11-11.md).
The [profile admission review](docs/reports/profile-admission-2026-11-11.md)
explains linked-state refusal and retained ordinary SQLite recovery.

### Existing command line

Requires Python 3.12–3.14 and the pinned Rust 1.98.1 toolchain (rustup). On Windows Rust's MSVC toolchain also needs Microsoft's C++ build tools. Building needs development tools, not administrator/network-capture privileges. The Python application runtime has no pip dependencies.

Use these commands from the repository root, in PowerShell or a POSIX shell:

~~~text
cargo build --release --locked
python -m ndal.cli demo out/demo
python -m ndal.cli analyze --capture out/demo/dns_burst.pcap --logs out/demo/connections.jsonl --output out/review --search 192.0.2.10
~~~

Open the generated report.html locally in a browser. This example produces two review hypotheses, one DNS burst and one periodic log connection pattern. Each output directory must be new; the application refuses to overwrite an earlier review. These are different synthetic event sources; do not merge equivalent capture/log copies or counts will be duplicated.

For setup, configuration, log format, troubleshooting and analyst workflow, see [usage](docs/usage.md). For explicit supported limits and omissions, see [contracts](docs/contracts.md). [Validation evidence](docs/reports/validation.md) distinguishes local results from CI.

## Analyst drilldown and stable pages

```text
python -m ndal.cli analyze --capture out/demo/dns_burst.pcap --logs out/demo/connections.jsonl --output out/query-first --query --query-rule dns_nxdomain_burst --query-protocol udp --query-severity review --query-limit 2
```

Open `query.html` or read `query.json` for exact nanosecond time/protocol/rule/severity filters, matched counts, original finding rationale and event IDs. Add inclusive `--query-start-ns` / `--query-end-ns` limits. For another page, rerun against the **same** inputs/policy/filters in a new directory with `--query-cursor <next_cursor>`. Equal timestamps use event ID as a stable tie-break. A cursor from changed evidence or filters is rejected.

Detections always run against the complete normalized input snapshot, then references are filtered; they are never recomputed on an artificially small page. Original detector evidence references can be capped at100; the full finding count stays visible and is not a claim that a page contains all related packets. Capture quality issues have no reliable event timestamps and remain visible as `capture_issues_unfiltered`, even on empty pages. A query is a human review aid, not proof of absence, attribution or live capture. No network/device interface is added.

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

The existing CLI stays available alongside the owner-local Tk workbench. Neither
interface adds a network server or capture driver. Read the [architecture decision](docs/architecture.md), [testing strategy](docs/testing.md), [threat model/security policy](docs/security.md), [performance methodology](docs/performance.md) and [primary research](docs/research.md).

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
| [docs/handbook.md](docs/handbook.md) | Network Defense Analysis Lab handbook. |
| [docs/native-workbench.md](docs/native-workbench.md) | Native Network Defense Analysis Workbench. |
| [docs/performance.md](docs/performance.md) | Complexity and benchmark methodology. |
| [docs/release.md](docs/release.md) | Release and maintenance checklist. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured synthetic Windows benchmark snapshot, not a throughput promise. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source CI job snapshot, not a future guarantee. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/installed-windows-1.1.0-2026-11-11.md](docs/reports/installed-windows-1.1.0-2026-11-11.md) | Installed Windows 1.1.0 validation · 11 November 2026. |
| [docs/reports/native-workbench-2026-11-11.md](docs/reports/native-workbench-2026-11-11.md) | Native workbench validation — November 11, 2026. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/profile-admission-2026-11-11.md](docs/reports/profile-admission-2026-11-11.md) | Native profile admission — November 11, 2026. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed Word project guide bound to the documented source revision. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact Office digests, visual review scopes and immutable source baselines. |
| [docs/reports/query-2026-11-09.md](docs/reports/query-2026-11-09.md) | Snapshot-bound analyst drilldown validation — November 9, 2026. |
| [docs/reports/validation.md](docs/reports/validation.md) | Validation and accepted-source evidence. |
| [docs/reports/windows-application-guide-1.1.0.docx](docs/reports/windows-application-guide-1.1.0.docx) | Current illustrated installed workbench guide with two real screenshots, exact source code and measured limits. |
| [docs/reports/windows-application-guide-1.1.0.json](docs/reports/windows-application-guide-1.1.0.json) | Current Word, screenshot, source and individually reviewed rendered-page digests. |
| [docs/research.md](docs/research.md) | Primary research and implementation rationale. |
| [docs/security.md](docs/security.md) | Threat model and security policy. |
| [docs/testing.md](docs/testing.md) | Testing strategy and acceptance gates. |
| [docs/usage.md](docs/usage.md) | Setup, analyst workflow and help. |
| [examples/desktop/custom-policy.json](examples/desktop/custom-policy.json) | Actual higher DNS-burst threshold example used by the native workbench; narrow allowlists remain empty. |
| [licenses/RUST-COPYRIGHT-library.html](licenses/RUST-COPYRIGHT-library.html) | Complete Rust1.98.1 standard-library copyright and dependency license notices from the actual pinned Windows toolchain, retained in portable notices. |
| [native/lib.rs](native/lib.rs) | Jason Stys: bounded classic-PCAP/Ethernet/IPv4/UDP/TCP/DNS metadata decoder. |
| [native/main.rs](native/main.rs) | Jason Stys: read one bounded regular capture file and emit safe versioned TSV metadata. |
| [native/tests.rs](native/tests.rs) | Jason Stys: independent native wire fixtures, boundary tests and deterministic mutation fuzzing. |
| [ndal/\_\_init\_\_.py](ndal/__init__.py) | Jason Stys: offline synthetic network evidence analysis, no runtime third-party packages. |
| [ndal/cli.py](ndal/cli.py) | Jason Stys: local bounded file analysis, synthetic demo generation and private no-overwrite evidence output. |
| [ndal/desktop.py](ndal/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [ndal/desktop\_io.py](ndal/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [ndal/desktop\_project.py](ndal/desktop_project.py) | Actual offline packet/log analysis, stable saved-snapshot pages and SQL evidence review. Jason Stys. |
| [ndal/desktop\_state.py](ndal/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [ndal/detect.py](ndal/detect.py) | Jason Stys: bounded explainable DNS/window/fan-out/periodicity hypotheses with scoped allowlists. |
| [ndal/inputs.py](ndal/inputs.py) | Bounded stable ordinary-file reads and streaming tool hashes for offline identity inputs. Jason Stys. |
| [ndal/model.py](ndal/model.py) | Jason Stys: strict immutable metadata models and native TSV/network-log trust boundaries. |
| [ndal/query.py](ndal/query.py) | Jason Stys: snapshot-bound analyst evidence drilldown with stable keyset pages and visible capture gaps. |
| [ndal/report.py](ndal/report.py) | Jason Stys: deterministic machine-readable and escaped inert HTML analyst reports, no active content. |
| [ndal/store.py](ndal/store.py) | Jason Stys: transactional metadata-only SQLite evidence store and parameterized search. |
| [ndal/synthetic.py](ndal/synthetic.py) | Jason Stys: deterministic synthetic wire/log fixtures with reserved addresses; never sends traffic. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict Python tooling and all-runtime-module branch/statement coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: exact development-only tools; Python runtime uses only the standard library. |
| [requirements-dev.lock](requirements-dev.lock) | Full universal hash-locked Python development dependency graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked Windows freezer tool graph; no runtime package installation at application launch. |
| [rust-toolchain.toml](rust-toolchain.toml) | Jason Stys: reproducible tested compiler; no automatic floating stable toolchain. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: reproducible bounded release-decoder and analysis timings; no universal performance claims. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: generate exact definition/variable line maps and verify Python function/class contracts. |
| [scripts/differential.py](scripts/differential.py) | Jason Stys: independent libpcap/tcpdump fixture conformance, synthetic files only and no live interfaces. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Actual frozen Tk widgets, Rust decoder, SQLite paging and persisted export acceptance. Jason Stys. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: private-evidence exclusion, exact links/pins and dependency-free/offline runtime gates. |
| [sql/schema.sql](sql/schema.sql) | Jason Stys: strict transactional metadata-only evidence schema with indexed human-review searches. |
| [sql/search.sql](sql/search.sql) | Jason Stys: exact source/hostname search uses bound values, never interpolated SQL or wildcard guesses. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: fail-closed wire/log/policy contracts, boundary semantics and bounded evidence property tests. |
| [tests/test\_current\_word\_publication.py](tests/test_current_word_publication.py) | Jason Stys: actual current Word XML remains inspected; unknown binary documents are not excluded. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Independent actual Rust/detector/SQLite/native-adapter and saved cursor oracles. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_native\_inputs.py](tests/test_native_inputs.py) | Actual descriptor identity, FIFO availability, resource bounds and minimal native environment. Jason Stys. |
| [tests/test\_pipeline.py](tests/test_pipeline.py) | Jason Stys: real Rust subprocess, labeled scenario, CLI privacy, evidence SQL and report integration tests. |
| [tests/test\_profile\_admission.py](tests/test_profile_admission.py) | Actual pre-existing alias refusal and ordinary SQLite recovery continuity. Jason Stys. |
| [tests/test\_publication\_policy.py](tests/test_publication_policy.py) | Jason Stys: independent real-ZIP publication privacy boundary and unknown-file rejection regressions. |
| [tests/test\_query.py](tests/test_query.py) | Jason Stys: independent keyset query, detector scope and capture-gap regression cases. |
| [tools.lock.json](tools.lock.json) | Official scanner versions, release URLs and pinned SHA256 digests. |

<!-- END FILE GUIDE -->

MIT licensed. Educational assurance is not a certification, production IDS, compliance attestation or substitute for an authorized security assessment.

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.

## Current Windows application guide

The published **1.1.0** app has a [four-page illustrated guide](docs/reports/windows-application-guide-1.1.0.docx) with actual installed screenshots, a worked user journey, important source excerpts and operating limits. Read the [installed validation report](docs/reports/installed-windows-1.1.0-2026-11-11.md) and [byte/page review manifest](docs/reports/windows-application-guide-1.1.0.json) for exact scope. Historical Office editions remain unchanged.

Added documentation:

- [docs/reports/windows-application-guide-1.1.0.docx](docs/reports/windows-application-guide-1.1.0.docx): installed application use, screenshots, source and measured validation.
- [docs/reports/windows-application-guide-1.1.0.json](docs/reports/windows-application-guide-1.1.0.json): exact Word, screenshot, immutable code and reviewed-page hashes.
- [docs/reports/installed-windows-1.1.0-2026-11-11.md](docs/reports/installed-windows-1.1.0-2026-11-11.md): observed installed workflows, distribution identity, data preservation and practical limits.
