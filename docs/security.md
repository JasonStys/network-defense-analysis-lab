# Threat model and security policy

Author: Jason Stys. Intended environment: an authorized developer's local account analyzing synthetic fixtures.

## Assets, threats and defenses

Protect source capture bytes, metadata, local reports, workstation integrity and repository credentials. Treat local captures, logs and policies as untrusted data, not instructions.

Length-checked slices and explicit Result errors defend against malformed packets. Byte/record/label/pointer limits, a native deadline and bounded evidence lists constrain exhaustion. Rust forbids unsafe code and has no external dependencies. Python checks exact schemas, integer/bool distinctions, duplicate keys/IDs and native packet accounting. SQLite uses strict constraints and bound search values; imports are transactional.

HTML escapes all data in a literal pre block. CSP default-src none, base-uri none and form-action none deny active resources; no script, frame, stylesheet, embedded media or form is generated. No local server, remote model/API, analytics or DNS lookup runs during analysis.

The trusted native binary has a fixed repo-built path, not a user-selected executable, shell command or input script. The CLI snapshots the exact read bytes before hashing/decoding. Files are bounded and regular; no capture driver or privileged port is opened. Output creation is exclusive/no-overwrite. POSIX ownership restrictions and Windows user-directory ACLs are important; this is not a sandbox against a hostile local OS administrator.

CI uses full-SHA action pins, read-only default permissions, no persisted checkout credentials, locked Python hashes and official hash-checked scanners. CodeQL alone gets security-events write. No artifact/database upload or Actions cache is configured. Publishing source does not publish local captures/keys/reports. Repository privacy gates complement secret scanning; they are not a guarantee that every possible secret format is detected.

## Residual risks and non-goals

No production packet corpus, complete protocol compliance, threat-intelligence enrichment, signed custody chain, data encryption, multi-user isolation or real-time detection is claimed. Resource limits are application bounds, not OS CPU/memory sandbox limits. Public library parse functions have byte/count limits; the 15-second deadline applies to the Python worker invocation. Concurrent modification of OS files or replacement of the trusted binary by the same account is outside this trust model. Local reports contain IP/name metadata and can still be sensitive.

Network checksums can be spoofed and altered; observed periodicity is not a maliciousness proof. NIC offload, duplicate/overlapping input sources, clock issues and truncated/unsupported traffic affect conclusions. Never interpret "no finding" as authorization or evidence of safety. See [contracts](contracts.md).

## Reporting issues

Do not post credentials, real packet captures or applicant/customer information in public issues. Provide a minimal synthetic reproducer and relevant version/issue code. Contact Jason Stys through [GitHub](https://github.com/JasonStys) or [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). No staffed response SLA or certification is promised.
