# Validation and accepted-source evidence

Author: Jason Stys. Recorded 2026-10-14 13:57:49 UTC. Accepted implementation: 6372878b0455d41a17e3e87fc4a604216ede8c03. All seven jobs passed; [machine-readable CI snapshot](ci.json) preserves job URLs, source SHA and actual timestamps rather than claiming success for a future self-referential commit.

## Actual results

| Check | Observed result |
| --- | --- |
| Native debug / release | 15 tests each, zero failures, includes 100,000 deterministic mutation cases per profile |
| Python integration/contracts/property | 70 cases pass; 200 Hypothesis examples within the property case |
| All runtime-module coverage | 99.52% combined statements/branches locally; all seven modules included, 95% gate enforced in every matrix job |
| OS/runtime matrix | Linux Python 3.12/3.14, Windows 3.14, macOS 3.14: all pass |
| Independent fixture decoding | 11 libpcap/tcpdump fixtures pass on Linux CI; tcpdump 4.99.4 |
| Format / static types / lint | Rust format, clippy warnings denied, Python Ruff/strict mypy: all pass |
| Dependency / secret / workflow | Complete hash-locked graph audit, dependency-free Cargo.lock, Gitleaks full history, actionlint: all pass |
| CodeQL | Python security-extended job passes; zero open alerts at acceptance |
| Bounded performance exercise | 1,000 / 5,000 / 20,000 packets; warmup + seven measured repetitions; actual counts and baseline findings/SQL verified |
| Documentation / privacy | Exact line maps, full tracked-file summaries, local links, offline/no-private-state/action-pin gates pass |

[Accepted Validate run](https://github.com/JasonStys/network-defense-analysis-lab/actions/runs/38575898731) and [accepted CodeQL run](https://github.com/JasonStys/network-defense-analysis-lab/actions/runs/38575898749) are immutable evidence for the implementation SHA above. Dynamic README badges reflect later commits; final documentation commits must also pass before handoff. First publication's full workflows passed as well; no failed hosted run was hidden or relabeled.

The local CLI demo generated 13 synthetic captures plus one log file, then produced JSON, inert HTML and SQLite evidence for 20 observations, zero parser issues and exactly the expected two review hypotheses (DNS burst and periodic log connections). SHA256 and exact-search results were verified by automated tests. These are synthetic-only local outputs, not publicly hosted services or real traffic.

## Performance snapshot and boundaries

[Measured Windows/AMD64 benchmark](benchmark.json), Python 3.14.6 / Rust 1.98.1, recorded 2026-10-14T13:49:12.599468+00:00. Decode medians (including process/file IO/TSV/normalization) were 0.03343s / 0.08945s / 0.37219s; separately timed rules/in-memory SQLite medians were 0.00603s / 0.02470s / 0.11721s. These are observations, not general guarantees or pure Rust throughput measurements. CI independently reruns this exercise. See [methodology](../performance.md).

Native coverage percentage and coverage-guided fuzzing are not claimed. Windows did not locally execute tcpdump; the independent comparison actually passed on hosted Linux. CodeQL covers Python, not Rust; Rust has native tests and clippy gates. No real-network accuracy rate, production IDS qualification or full protocol compliance is claimed.

## Corrections and release hygiene

Development checks caught strict type errors and unclosed SQLite test connections; these were fixed, not suppressed. Temporary test files were redirected into the writable workspace. Sliding-window peaks save coordinates to avoid quadratic copies. Review tightened nonstring protocol rejection, JSON recursion handling, canonical no-wildcard allowlist names, huge-integer metric bounds, controlled SQLite errors, DNS TC loss and IPv4 reserved flags. Regression tests pass.

This repo has zero Actions artifacts and zero Actions caches at acceptance. Its workflows do not upload artifacts/CodeQL databases or use Actions caches. Account-level storage checks stay local/private; no old runs/caches were deleted or billing/retention settings changed. No real captures, credentials, private reports or generated databases are tracked. Documentation-only handoff changes are independently rechecked on final main.
