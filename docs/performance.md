# Complexity and benchmark methodology

Author: Jason Stys. Complexity describes this bounded implementation, not every possible network detector.

Rust parsing visits container/frame bytes and bounded DNS names/records. For B input bytes and P packets, O(B + P) work with constant bounded DNS hop/record limits; input snapshot and returned metadata require O(B + P) storage. Checksums are linear in inspected bytes. The CLI may hold input and native output simultaneously; caps bound allocations but are not an OS memory sandbox.

Python event sorting is O(N log N). Each source/client group uses an O(N) sliding deque/counted multiset. Maximum window coordinates are saved and copied **once**, avoiding quadratic copies when a burst grows. Entropy uses a ≤63-character Counter. Periodicity examines each bounded group once. Findings cap references to 100 IDs but retain counts. Indexed SQL import is approximately O(N log N); exact query predicates use indexes where supported, with an explicit result limit. OR predicates and ordering can require multiple index scans/sorting; no unmeasured constant-time query claim.

scripts/benchmark.py measures synthetic UDP telemetry at 1,000 / 5,000 / 20,000 records, one warmup and seven repeats each, with the optimized release decoder. Generation is excluded. Decode phase includes process startup, private temporary-file IO, native parsing/checksums/TSV emission and Python normalization. Analysis phase is measured **separately**, includes detection and in-memory SQLite insertion/count verification, and excludes report serialization and SQLite backup. There are no live sockets, coverage instrumentation, memory tracing or profiler overhead in the benchmark.

Every iteration checks decoded count, no parser issues, no baseline findings and SQL row count. Raw seconds, medians, corpus byte count, host OS/runtime and observed packets/second are recorded. This is a representative baseline, not an adversarial DNS throughput test, peak resident-memory measurement, scalability certification or performance comparison against tcpdump.

CI prints its own measurements without artifact uploads. [Committed benchmark snapshot](reports/benchmark.json) is the actual local Windows measurement; repeated runs/other machines naturally differ. Runtime deadline/cardinality checks are enforceable gates; shared-runner timing is not arbitrarily turned into a pass/fail target.
