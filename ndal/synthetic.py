"""Jason Stys: deterministic synthetic wire/log fixtures with reserved addresses; never sends traffic."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CASES — line 70
# variable: EXPECTED — line 85
# definition: checksum — line 102
# parameter: data — line 102
# variable: data — line 105
# variable: total — line 106
# variable: total — line 108
# definition: dns — line 112
# parameter: name — line 112
# parameter: rcode — line 112
# parameter: response — line 112
# variable: labels — line 114
# variable: label — line 115
# variable: label — line 119
# definition: frame — line 124
# parameter: src — line 125
# parameter: dst — line 126
# parameter: sport — line 127
# parameter: dport — line 128
# parameter: payload — line 129
# parameter: tcp — line 130
# parameter: flags — line 131
# variable: destination — line 134
# variable: source — line 134
# variable: protocol — line 138
# variable: transport — line 139
# variable: check — line 144
# variable: offset — line 150
# variable: transport — line 151
# variable: header — line 154
# variable: header — line 167
# definition: pcap — line 171
# parameter: packets — line 172
# parameter: little — line 173
# parameter: nano — line 174
# parameter: truncated — line 175
# variable: endian — line 178
# variable: result — line 179
# variable: data — line 184
# variable: time_ns — line 184
# definition: scenario — line 198
# parameter: case — line 198
# variable: packets — line 202
# variable: index — line 204
# variable: dst — line 205
# variable: interval — line 206
# variable: packets — line 220
# variable: index — line 231
# variable: packets — line 245
# variable: packets — line 247
# variable: index — line 249
# variable: packets — line 262
# definition: log_sample — line 281
# variable: events — line 283
# variable: index — line 295
# variable: value — line 298
# END CODE MAP

from __future__ import annotations

import ipaddress
import json
import struct
from dataclasses import asdict

from ndal.model import Event

CASES = (
    "office_baseline",
    "industrial_telemetry",
    "dns_burst",
    "dns_long_label",
    "port_fanout",
    "periodic_connections",
    "mixed_hosts",
    "sparse_failures",
    "syn_ack_only",
    "malformed_dns",
    "truncated_packet",
    "ipv6_unsupported",
    "reordered",
)
EXPECTED = {
    "office_baseline": set(),
    "industrial_telemetry": set(),
    "dns_burst": {"dns_nxdomain_burst"},
    "dns_long_label": {"dns_long_label"},
    "port_fanout": {"tcp_port_fanout"},
    "periodic_connections": {"tcp_periodicity"},
    "mixed_hosts": set(),
    "sparse_failures": set(),
    "syn_ack_only": set(),
    "malformed_dns": {"capture_quality"},
    "truncated_packet": {"capture_quality"},
    "ipv6_unsupported": {"capture_quality"},
    "reordered": {"capture_quality"},
}


def checksum(data: bytes) -> int:
    """Independent one's-complement fixture checksum, including an odd-byte pad."""
    if len(data) % 2:
        data += b"\0"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def dns(name: str, response: bool = False, rcode: int = 0) -> bytes:
    """Create a simple one-question DNS fixture (no answer claims), bounded hostname labels."""
    labels = name.encode("ascii").split(b".") if name else []
    if any(not 1 <= len(label) <= 63 for label in labels) or len(name) > 253:
        raise ValueError("synthetic hostname limit")
    return (
        struct.pack("!6H", 1, 0x8100 | rcode if response else 0x0100, 1, 0, 0, 0)
        + b"".join(bytes([len(label)]) + label for label in labels)
        + b"\0\0\1\0\1"
    )


def frame(
    src: str = "192.0.2.10",
    dst: str = "192.0.2.53",
    sport: int = 40000,
    dport: int = 53,
    payload: bytes = b"",
    tcp: bool = False,
    flags: int = 2,
) -> bytes:
    """Build valid Ethernet/IPv4/transport checksums without sockets; addresses are fixture arguments."""
    source, destination = (
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    protocol = 6 if tcp else 17
    transport = (
        struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0) + payload
        if tcp
        else struct.pack("!4H", sport, dport, 8 + len(payload), 0) + payload
    )
    check = checksum(
        source
        + destination
        + struct.pack("!BBH", 0, protocol, len(transport))
        + transport
    )
    offset = 16 if tcp else 6
    transport = (
        transport[:offset] + struct.pack("!H", check or 65535) + transport[offset + 2 :]
    )
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        1,
        0,
        64,
        protocol,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return b"\x02\0\0\0\0\x01\x02\0\0\0\0\x02\x08\0" + header + transport


def pcap(
    packets: list[tuple[int, bytes]],
    little: bool = True,
    nano: bool = False,
    truncated: bool = False,
) -> bytes:
    """Serialize packet tuples (nanoseconds, bytes) as classic PCAP; optional intentional snapshot loss."""
    endian = "<" if little else ">"
    result = bytearray(
        struct.pack(
            endian + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
        )
    )
    for time_ns, data in packets:
        result.extend(
            struct.pack(
                endian + "4I",
                time_ns // 1_000_000_000,
                time_ns % 1_000_000_000 // (1 if nano else 1000),
                len(data),
                len(data) + int(truncated),
            )
        )
        result.extend(data)
    return bytes(result)


def scenario(case: str) -> bytes:
    """Create labeled positive/negative industrial/office cases; malformed samples are deliberate."""
    if case not in CASES:
        raise ValueError("unknown synthetic scenario")
    packets = []
    if case in {"dns_burst", "sparse_failures", "mixed_hosts"}:
        for index in range(10):
            dst = f"192.0.2.{10 + index}" if case == "mixed_hosts" else "192.0.2.10"
            interval = 61 if case == "sparse_failures" else 1
            packets.append(
                (
                    index * interval * 1_000_000_000,
                    frame(
                        src="192.0.2.53",
                        dst=dst,
                        sport=53,
                        dport=40000,
                        payload=dns(f"old{index}.example", True, 3),
                    ),
                )
            )
    elif case == "dns_long_label":
        packets = [
            (
                0,
                frame(
                    payload=dns(
                        "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl.example"
                    )
                ),
            )
        ]
    elif case in {"port_fanout", "periodic_connections", "syn_ack_only"}:
        for index in range(10):
            packets.append(
                (
                    index * 5_000_000_000,
                    frame(
                        dst="198.51.100.20",
                        sport=40000 + index,
                        dport=1000 + index if case == "port_fanout" else 443,
                        tcp=True,
                        flags=18 if case == "syn_ack_only" else 2,
                    ),
                )
            )
    elif case == "malformed_dns":
        packets = [(0, frame(payload=b"bad"))]
    elif case == "ipv6_unsupported":
        packets = [(0, b"\0" * 12 + b"\x86\xdd" + b"\0" * 40)]
    elif case == "industrial_telemetry":
        for index in range(30):
            packets.append(
                (
                    index * 1_000_000_000,
                    frame(
                        src="192.0.2.30",
                        dst="192.0.2.31",
                        dport=2001,
                        payload=b"synthetic temperature=21.4C",
                    ),
                )
            )
    else:
        packets = [
            (0, frame(payload=dns("catalog.example"))),
            (
                7_000_000_000,
                frame(
                    src="192.0.2.53",
                    dst="192.0.2.10",
                    sport=53,
                    dport=40000,
                    payload=dns("catalog.example", True),
                ),
            ),
            (12_000_000_000, frame(dst="198.51.100.20", dport=443, tcp=True)),
        ]
        if case == "reordered":
            packets.reverse()
    return pcap(packets, truncated=case == "truncated_packet")


def log_sample() -> bytes:
    """Equivalent normalized synthetic log events, suitable for a distinct log-only source."""
    events = [
        Event(
            f"log-{index}",
            index * 5_000_000_000,
            "203.0.113.10",
            "203.0.113.20",
            40000 + index,
            443,
            "tcp",
            2,
            40,
        )
        for index in range(10)
    ]
    return (
        "\n".join(json.dumps(asdict(value), sort_keys=True) for value in events) + "\n"
    ).encode()
