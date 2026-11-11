# Native Network Defense Analysis Workbench

Created by Jason Stys. The Windows portable app contains the actual Rust decoder,
Python detectors, SQLite evidence store, Tk interface and patched Python runtime.
It needs no separately installed Python, Rust, Node, packet driver or terminal.
This recipe builds a portable EXE; it does not create a signed installer.

## Analyst workflow

1. Open `NetworkDefenseAnalysisLab.exe`. Choose a prepared fictional scenario in
   **Inputs and analysis**, or choose your permitted classic PCAP and/or normalized
   JSONL files. Select the thresholds/allowlists JSON. Capture and logs must be
   distinct sources; duplicate representations would double counts.
2. Review exact filters, page size and optional IPv4/hostname search. Times are
   inclusive integer nanoseconds, not an inferred wall clock. Acknowledge permission
   and choose **Run selected analysis**.
3. In **Findings and timeline**, switch between full-snapshot hypotheses, selected
   evidence, unfiltered capture issues, exact SQL search and cursor metadata.
   Selecting a row shows its complete literal original record. Search filters this
   view; it does not rerun detections on a conveniently small subset.
4. Choose **Prepare next evidence page** to fill the ordinary controls with the
   selected saved snapshot's exact filters and next cursor. Review and run. To
   change a filter, clear the cursor. A mismatching cursor is rejected. Source
   files need not remain available to page the already retained normalized snapshot.
5. Export the exact selected bundle to a new directory. Open **Saved analyses**
   after a normal exit to inspect prior outputs without re-decoding. Confirmed
   deletion removes only that profile's selected local bundle, not prior exports.

The prepared malformed-capture case intentionally retains capture-quality findings.
The benign office and industrial examples have no suspicious-pattern finding. The
custom threshold example changes the actual configured DNS threshold rather than
substituting a precomputed result. Optional prepared files are generated from the
original authored synthetic generator inside this same profile; edited files are
retained and preparation refuses to overwrite them.

## Private data and ownership

The version-independent Windows profile is
`%LOCALAPPDATA%\JasonStys\NetworkDefenseAnalysisLab`. An explicit `--profile`
path remains available for authorized custom/synthetic workspaces. It must remain
outside the app installation and have the expected product marker. One owner lock
protects each profile; no unknown nonempty directory is reset. History is bounded
to 20 completed runs, 32 MiB per file, 64 MiB per bundle and 128 MiB total retained
payload. Export before deliberately removing old work when capacity is reached.

Reports and SQL exports contain normalized metadata, not original packet payloads;
addresses, domains and findings can still be sensitive. Local files are plaintext
for the trusted OS owner, not encryption or multiuser authorization. Back up the
whole external profile only after a normal exit. **Exit application** waits for
the current bounded analysis and transaction. There are no scans, live captures,
DNS requests, cloud calls, automatic blocking, ads or background uploads.

The Rust parser remains classic PCAP/Ethernet/IPv4 metadata only; unsupported,
malformed and incomplete records remain explicit. Detector references may be
capped at 100 even though the original total evidence count remains visible. A
review hypothesis is not attack attribution; missing findings do not prove safety.
Cursor hashes bind snapshot/filter content, not authenticated source acquisition.

## Build and validate

Use a reviewed Windows CPython **3.14.10** SDK with Tk and the exact Rust **1.98.1**
toolchain. Keep development environments and download caches outside product data.

```text
python -m pip install --require-hashes -r requirements-dev.lock -r requirements-native.lock
python scripts/build_native.py
python scripts/test_native_app.py
```

The builder compiles the dependency-free Rust decoder and binds the actual decoder,
Python DLL, SQL, policy, notices and icon hashes to source commit/dirty-state metadata.
It retains actual Python, Tcl/Tk and PyInstaller license/exception texts plus the
complete Rust 1.98.1 standard-library copyright/dependency notice inventory. The
fixed local license viewer accepts up to 2 MiB to hold that approximately 1.5 MiB
inventory; report, input and history limits are unchanged. The actual
EXE acceptance drives the same widgets, handlers, worker and Tk mainloop across
eight workflows, two launches, source-bound pages, external logs, exact exports,
malformed-input retention and normal owned-process exit. It uses a fresh marked
synthetic profile, never the normal default profile. Missing prerequisites fail.
Linux/macOS source tests remain separate from Windows desktop acceptance.
