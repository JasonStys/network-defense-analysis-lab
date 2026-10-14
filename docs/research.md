# Primary research and implementation rationale

Researched 2026-10-14 by Jason Stys. These sources inform contracts, not instructions granting access to networks.

- [libpcap savefile specification](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in): container headers, byte order, timestamp resolution and link/FCS flags. Its maintained-library recommendation motivated the explicit educational-parser limitation and independent conformance check.
- [DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): message layout, name compression and size constraints. This implementation supports a narrow hostname/question/envelope subset, not complete DNS semantics.
- [IPv4 RFC 791](https://www.rfc-editor.org/rfc/rfc791) and [UDP RFC 768](https://www.rfc-editor.org/rfc/rfc768): header lengths, fragmentation and checksum/pseudoheader handling.
- [TCP RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293): transport header/checksum and flags; this lab intentionally does not reassemble streams.
- [Rust Result error handling](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html) and [Cargo build workflow](https://doc.rust-lang.org/cargo/guide/working-on-an-existing-project.html): explicit recoverable errors, compiler-checked slices and reproducible native builds.
- [Python sqlite3](https://docs.python.org/3.14/library/sqlite3.html): bound parameters, transactions, backup and explicit connection closure.
- [SQLite strict tables](https://sqlite.org/stricttables.html): reject type inconsistencies at the database boundary, not just in a UI.
- [RFC 5737 documentation addresses](https://datatracker.ietf.org/doc/html/rfc5737) and [RFC 2606 reserved DNS names](https://datatracker.ietf.org/doc/html/rfc2606): fixtures use documentation-only address ranges and .example labels without transmitting traffic.

Detection thresholds and entropy/periodicity rules are authored teaching heuristics, not official IOC intelligence, validated industry accuracy rates or evidence of malware. Negative cases, explicit limitations and analyst alternatives are essential.
