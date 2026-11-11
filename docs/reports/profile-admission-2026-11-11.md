# Native profile admission — November 11, 2026

Created by Jason Stys. The not-yet-published native 1.1.0 workbench retains
the original Rust decoder, Python detectors, SQL queries, schemas and CLI paths.

Every existing fixed marker, lock, history database and SQLite `-journal`, `-wal`
and `-shm` entry is admitted before initialization as an ordinary one-link file.
Symbolic/reparse links, hardlinks and nonregular entries are refused without
deleting or replacing the selected path. Each later connection repeats database
and sidecar admission. This follows an actual shared-workspace fixture in which
SQLite modified an outside inert file through a pre-existing shared-memory
hardlink. All fixture files were within one disposable owned test root.

Independent fixtures use actual hardlinks/directories for all six entries,
symbolic and dangling links where the OS permits, and actual SQLite committed-WAL
and hot-journal recovery. Correct history/output must survive recovery unchanged.
Missing ordinary files can still be created, and valid sidecars are not removed.

This bounds pre-existing accidental alias admission, not arbitrary concurrent
same-OS-owner replacements, administrator threats, encryption or authentication.
The first native feature commit's measured source/native evidence stays historical;
the final guarded candidate requires fresh clean-source actual executable and
hosted validation. No normal profile, installed application or release was changed.

The complete guarded source suite on CPython 3.14.10 / Windows passed **153 tests**
with three explicit platform-limited skips (one actual POSIX FIFO case and two
Windows symbolic-link setup refusals). Combined line/branch coverage was **96.57%**
against the unchanged 95% floor. Strict types, lint, formatting, source maps,
file inventory and privacy/link/pin checks passed. These are source observations;
actual frozen consumer and hosted outcomes are separate source-bound evidence.
