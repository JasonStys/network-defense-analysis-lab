-- Jason Stys: strict transactional metadata-only evidence schema with indexed human-review searches.
-- BEGIN CODE MAP (generated; python scripts/code_map.py)
-- SQL object: events — line 24
-- column: identifier — line 25
-- column: time_ns — line 26
-- column: src — line 27
-- column: dst — line 28
-- column: sport — line 29
-- column: dport — line 30
-- column: protocol — line 31
-- column: flags — line 32
-- column: bytes — line 33
-- column: name — line 34
-- column: response — line 35
-- column: rcode — line 36
-- column: qtype — line 37
-- SQL object: events_src_time — line 39
-- SQL object: events_dns_client_time — line 40
-- SQL object: issues — line 41
-- column: packet — line 42
-- column: code — line 43
-- END CODE MAP
PRAGMA foreign_keys = ON;
CREATE TABLE events (
    identifier TEXT PRIMARY KEY,
    time_ns INTEGER NOT NULL CHECK(time_ns >= 0),
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    sport INTEGER NOT NULL CHECK(sport BETWEEN 0 AND 65535),
    dport INTEGER NOT NULL CHECK(dport BETWEEN 0 AND 65535),
    protocol TEXT NOT NULL CHECK(protocol IN ('udp','tcp')),
    flags INTEGER NOT NULL CHECK(flags BETWEEN 0 AND 255),
    bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND 65535),
    name TEXT,
    response INTEGER CHECK(response IN (0,1)),
    rcode INTEGER CHECK(rcode BETWEEN 0 AND 15),
    qtype INTEGER CHECK(qtype BETWEEN 0 AND 65535)
) STRICT;
CREATE INDEX events_src_time ON events(src, time_ns, identifier);
CREATE INDEX events_dns_client_time ON events(dst, time_ns) WHERE response = 1;
CREATE TABLE issues (
    packet INTEGER NOT NULL CHECK(packet > 0),
    code TEXT NOT NULL,
    PRIMARY KEY(packet, code)
) STRICT;
