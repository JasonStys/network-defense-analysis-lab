# Validation report

Author: Jason Stys. Local implementation validation is complete; initial publishing/hosted CI verification is pending. This report will be updated with immutable accepted-source evidence before handoff.

Locally: 15 native tests pass in debug and release, including 100,000 deterministic mutation cases per profile. 68 Python cases pass and all seven runtime modules are included in combined statement/branch coverage (99.52%). Strict types, Rust clippy, format/lint and full locked dependency audit pass. No known dependency vulnerability was reported; this is a time-bound scanner observation, not a safety guarantee.

Three benchmark sizes and seven measured repeats plus warmup passed exact decode/SQL baseline checks. Independent tcpdump conformance is Linux CI-only; it is not claimed as locally executed on this Windows PC.

Corrections during development: strict type errors, explicit connection closure in tests and workspace-local temporary paths were fixed before publication. A sliding-window implementation was improved to save coordinates rather than copy each growing maximum. Native DNS incomplete-message and IPv4 reserved-flag cases were added. No test failure was suppressed to obtain green output.

Artifacts/caches will not be uploaded. The account included-storage meter was full at the initial check; no old run/cache deletion, retention or billing change was performed. Local private outputs remain outside the tracked inventory.
