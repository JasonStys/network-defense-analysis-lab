//! Jason Stys: independent native wire fixtures, boundary tests and deterministic mutation fuzzing.
// BEGIN CODE MAP (generated; python scripts/code_map.py)
// field/parameter: payload — line 101
// field/parameter: port — line 101
// fn: udp — line 101
// binding: size — line 102
// binding: transport — line 103
// field/parameter: protocol — line 112
// field/parameter: transport — line 112
// fn: ipv4 — line 112
// binding: data — line 113
// binding: check — line 121
// field/parameter: frame — line 128
// field/parameter: little — line 128
// field/parameter: nano — line 128
// fn: pcap — line 128
// binding: result — line 129
// loop binding: value — line 130
// fn: question — line 153
// fn: endian_and_resolution — line 162
// loop binding: little — line 163
// loop binding: nano — line 164
// binding: parsed — line 165
// fn: all_prefixes — line 181
// binding: seed — line 182
// loop binding: length — line 183
// binding: _ — line 184
// fn: container_rejections — line 191
// binding: seed — line 192
// loop binding: expected — line 193
// loop binding: offset — line 193
// loop binding: value — line 193
// binding: data — line 200
// binding: data — line 207
// fn: snapshot_truncation — line 218
// binding: seed — line 219
// binding: length — line 220
// binding: result — line 222
// fn: packet_rejections — line 229
// loop binding: data — line 230
// loop binding: expected — line 230
// binding: data — line 244
// fn: transport_checksums — line 254
// binding: frame — line 255
// binding: check — line 256
// fn: dns_boundaries — line 269
// binding: seed — line 270
// loop binding: length — line 271
// binding: answer — line 274
// loop binding: expected — line 281
// loop binding: offset — line 281
// loop binding: value — line 281
// binding: data — line 288
// binding: data — line 292
// binding: cycle — line 295
// binding: oversized — line 299
// loop binding: _ — line 301
// fn: malformed_dns_keeps_flow — line 311
// binding: capture — line 312
// fn: reordered_timestamps — line 320
// binding: seed — line 321
// binding: second — line 322
// binding: capture — line 325
// fn: packet_limit — line 332
// binding: seed — line 333
// binding: record — line 334
// loop binding: _ — line 335
// fn: deterministic_mutation_fuzz — line 343
// binding: seed — line 344
// binding: state — line 345
// field/parameter: state — line 345
// loop binding: iteration — line 346
// binding: data — line 350
// binding: position — line 351
// binding: _ — line 359
// binding: _ — line 360
// fn: ipv4_boundaries — line 366
// loop binding: bytes — line 367
// loop binding: expected — line 367
// loop binding: offset — line 367
// binding: data — line 375
// binding: check — line 378
// binding: data — line 385
// fn: tcp_boundaries — line 395
// binding: transport — line 396
// binding: check — line 401
// binding: data — line 403
// binding: result — line 404
// fn: fatal_after_valid_record — line 427
// binding: data — line 428
// binding: data — line 431
// binding: data — line 434
// fn: dns_extended_boundaries — line 441
// binding: data — line 442
// binding: root — line 447
// binding: cycle — line 451
// END CODE MAP
use super::*;

/// Build a checksum-correct Ethernet/IPv4/UDP datagram entirely in memory.
fn udp(payload: &[u8], port: u16) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut transport = vec![0u8; size];
    transport[..2].copy_from_slice(&12345u16.to_be_bytes());
    transport[2..4].copy_from_slice(&port.to_be_bytes());
    transport[4..6].copy_from_slice(&(size as u16).to_be_bytes());
    transport[8..].copy_from_slice(payload);
    ipv4(&transport, 17)
}

/// Independent IPv4 envelope with reserved documentation addresses and valid header checksum.
fn ipv4(transport: &[u8], protocol: u8) -> Vec<u8> {
    let mut data = vec![0u8; 34];
    data[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    data[14] = 0x45;
    data[16..18].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
    data[22] = 64;
    data[23] = protocol;
    data[26..30].copy_from_slice(&[192, 0, 2, 10]);
    data[30..34].copy_from_slice(&[192, 0, 2, 53]);
    let check = checksum(&[&data[14..]]);
    data[24..26].copy_from_slice(&check.to_be_bytes());
    data.extend_from_slice(transport);
    data
}

/// Build classic PCAP independently for every endian/time variant.
fn pcap(frame: &[u8], little: bool, nano: bool) -> Vec<u8> {
    let mut result = Vec::new();
    for value in [
        if nano { 0xa1b23c4d_u32 } else { 0xa1b2c3d4 },
        if little { 0x00040002 } else { 0x00020004 },
        0,
        0,
        65535,
        1,
        1,
        42,
        frame.len() as u32,
        frame.len() as u32,
    ] {
        result.extend(if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        });
    }
    result.extend(frame);
    result
}

/// A literal single-question DNS packet, independent of the Python generator.
fn question() -> Vec<u8> {
    vec![
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 0, 0, 1, 0, 1,
    ]
}

#[test]
/// All four container magics decode equal metadata with accurate subsecond units.
fn endian_and_resolution() {
    for little in [false, true] {
        for nano in [false, true] {
            let parsed = parse(&pcap(&udp(&question(), 53), little, nano)).unwrap();
            assert!(parsed.issues.is_empty());
            assert_eq!(
                parsed.observations[0].time_ns,
                1_000_000_000 + if nano { 42 } else { 42_000 }
            );
            assert_eq!(
                parsed.observations[0].dns.as_ref().unwrap().name,
                "www.example"
            );
        }
    }
}

#[test]
/// Every truncated prefix must either return a structured result or a stable error, never panic.
fn all_prefixes() {
    let seed = pcap(&udp(&question(), 53), true, false);
    for length in 0..seed.len() {
        let _ = parse(&seed[..length]);
    }
    assert_eq!(parse(&seed[..24]).unwrap().packets, 0);
}

#[test]
/// Corrupt global headers and impossible record metadata fail closed, not partial success.
fn container_rejections() {
    let seed = pcap(&udp(&question(), 53), true, false);
    for (offset, value, expected) in [
        (0, 0, "unsupported_capture"),
        (4, 3, "capture_version"),
        (20, 2, "unsupported_linktype"),
        (16, 0, "capture_snaplen"),
        (32, 255, "record_length"),
    ] {
        let mut data = seed.clone();
        data[offset] = value;
        if offset == 16 {
            data[16..20].fill(0);
        }
        assert_eq!(parse(&data).unwrap_err(), expected);
    }
    let mut data = seed.clone();
    data[28..32].copy_from_slice(&1_000_000u32.to_le_bytes());
    assert_eq!(parse(&data).unwrap_err(), "capture_timestamp");
    assert_eq!(
        parse(&vec![0; MAX_BYTES + 1]).unwrap_err(),
        "capture_byte_limit"
    );
}

#[test]
/// Captured/original inequality is a visible issue, not a falsely decoded packet.
fn snapshot_truncation() {
    let mut seed = pcap(&udp(&question(), 53), true, false);
    let length = u32::from_le_bytes(seed[36..40].try_into().unwrap());
    seed[36..40].copy_from_slice(&(length + 1).to_le_bytes());
    let result = parse(&seed).unwrap();
    assert!(result.observations.is_empty());
    assert_eq!(result.issues[0].code, "capture_packet_truncated");
}

#[test]
/// Malformed and unsupported frames become stable packet issues.
fn packet_rejections() {
    for (data, expected) in [
        (vec![0; 13], "ethernet_truncated"),
        (vec![0; 14], "unsupported_ethertype"),
        (ipv4(&[0; 7], 17), "udp_truncated"),
        (ipv4(&[0; 19], 6), "tcp_truncated"),
        (ipv4(&[0; 8], 17), "udp_length"),
        (ipv4(&[0; 20], 6), "tcp_header"),
        (ipv4(&[], 1), "unsupported_transport"),
    ] {
        assert_eq!(
            parse(&pcap(&data, true, false)).unwrap().issues[0].code,
            expected
        );
    }
    let mut data = udp(&[], 123);
    data[24] ^= 1;
    assert_eq!(
        parse(&pcap(&data, true, false)).unwrap().issues[0].code,
        "ipv4_checksum"
    );
}

#[test]
/// Nonzero UDP checksum verifies; zero checksum is allowed in IPv4, corrupt nonzero fails.
fn transport_checksums() {
    let mut frame = udp(&[42], 123);
    let check = checksum(&[&frame[26..34], &[0, 17, 0, 9], &frame[34..]]);
    frame[40..42].copy_from_slice(&check.to_be_bytes());
    assert!(parse(&pcap(&frame, true, false)).unwrap().issues.is_empty());
    frame[42] ^= 1;
    assert_eq!(
        parse(&pcap(&frame, true, false)).unwrap().issues[0].code,
        "udp_checksum"
    );
    assert_eq!(checksum(&[&[1], &[2, 3]]), checksum(&[&[1, 2, 3]]));
}

#[test]
/// DNS validates answer compression, section counts, class, trailing bytes and malicious pointers.
fn dns_boundaries() {
    let seed = question();
    for length in 0..seed.len() {
        assert!(dns(&seed[..length]).is_err());
    }
    let mut answer = seed.clone();
    answer[2] = 0x81;
    answer[7] = 1;
    answer.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1]);
    assert!(dns(&answer).unwrap().response);
    answer.pop();
    assert_eq!(dns(&answer).unwrap_err(), "dns_truncated");
    for (offset, value, expected) in [
        (4, 1, "dns_unsupported"),
        (12, 0x80, "dns_label"),
        (13, 0, "dns_label"),
        (27, 1, "dns_unsupported"),
        (6, 1, "dns_record_limit"),
    ] {
        let mut data = seed.clone();
        data[offset] = value;
        assert_eq!(dns(&data).unwrap_err(), expected);
    }
    let mut data = seed.clone();
    data.extend([0]);
    assert_eq!(dns(&data).unwrap_err(), "dns_trailing");
    let mut cycle = vec![0; 12];
    cycle.extend([0xc0, 12, 0, 1, 0, 1]);
    cycle[5] = 1;
    assert_eq!(dns(&cycle).unwrap_err(), "dns_pointer");
    let mut oversized = vec![0; 12];
    oversized[5] = 1;
    for _ in 0..4 {
        oversized.push(63);
        oversized.extend([b'a'; 63]);
    }
    oversized.extend([0, 0, 1, 0, 1]);
    assert_eq!(dns(&oversized).unwrap_err(), "dns_name_limit");
}

#[test]
/// DNS failure preserves the valid transport observation and marks the loss of DNS evidence.
fn malformed_dns_keeps_flow() {
    let capture = parse(&pcap(&udp(&[0], 53), true, false)).unwrap();
    assert_eq!(capture.observations.len(), 1);
    assert!(capture.observations[0].dns.is_none());
    assert_eq!(capture.issues[0].code, "dns_truncated");
}

#[test]
/// Reordered timestamps stay visible; downstream windows must sort evidence by event time.
fn reordered_timestamps() {
    let mut seed = pcap(&udp(&[], 123), true, false);
    let mut second = seed[24..].to_vec();
    second[..8].fill(0);
    seed.extend(second);
    let capture = parse(&seed).unwrap();
    assert_eq!(capture.packets, 2);
    assert_eq!(capture.issues[0].code, "timestamp_reordered");
}

#[test]
/// The record cap is enforced even for zero-length frames, preventing output amplification.
fn packet_limit() {
    let mut seed = pcap(&[], true, false);
    let record = seed[24..].to_vec();
    for _ in 0..MAX_PACKETS {
        seed.extend(&record);
    }
    assert_eq!(parse(&seed).unwrap_err(), "capture_packet_limit");
}

#[test]
/// Fixed-seed byte mutations/deletions/appends exercise actual parsers; not coverage-guided fuzzing.
fn deterministic_mutation_fuzz() {
    let seed = pcap(&udp(&question(), 53), true, false);
    let mut state: u64 = 0x514b_197d_29e6_410f;
    for iteration in 0..100_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut data = seed.clone();
        let position = state as usize % data.len();
        data[position] = (state >> 32) as u8;
        if iteration % 3 == 0 {
            data.truncate(position);
        }
        if iteration % 5 == 0 {
            data.extend(state.to_le_bytes());
        }
        let _ = parse(&data);
        let _ = dns(&data);
    }
}

#[test]
/// Independent checksum repair exercises IP lengths, fragment/reserved flags and header truncation.
fn ipv4_boundaries() {
    for (offset, bytes, expected) in [
        (14, vec![0x44], "ipv4_header"),
        (14, vec![0x65], "ipv4_header"),
        (16, vec![0, 19], "ipv4_length"),
        (16, vec![0xff, 0xff], "ipv4_length"),
        (20, vec![0x20, 0], "unsupported_fragment"),
        (20, vec![0x80, 0], "ipv4_reserved_flag"),
    ] {
        let mut data = udp(&[], 123);
        data[offset..offset + bytes.len()].copy_from_slice(&bytes);
        data[24..26].fill(0);
        let check = checksum(&[&data[14..34]]);
        data[24..26].copy_from_slice(&check.to_be_bytes());
        assert_eq!(
            parse(&pcap(&data, true, false)).unwrap().issues[0].code,
            expected
        );
    }
    let mut data = udp(&[], 123);
    data.truncate(30);
    assert_eq!(
        parse(&pcap(&data, true, false)).unwrap().issues[0].code,
        "ipv4_truncated"
    );
}

#[test]
/// Valid TCP DNS is retained as a flow but never misinterpreted as supported UDP DNS.
fn tcp_boundaries() {
    let mut transport = vec![0; 20];
    transport[..2].copy_from_slice(&40000u16.to_be_bytes());
    transport[2..4].copy_from_slice(&53u16.to_be_bytes());
    transport[12] = 0x50;
    transport[13] = 2;
    let check = checksum(&[&[192, 0, 2, 10, 192, 0, 2, 53], &[0, 6, 0, 20], &transport]);
    transport[16..18].copy_from_slice(&check.to_be_bytes());
    let data = ipv4(&transport, 6);
    let result = parse(&pcap(&data, true, false)).unwrap();
    assert_eq!(result.issues[0].code, "unsupported_dns_tcp");
    assert_eq!(result.observations[0].flags, 2);
    transport[19] ^= 1;
    assert_eq!(
        parse(&pcap(&ipv4(&transport, 6), true, false))
            .unwrap()
            .issues[0]
            .code,
        "tcp_checksum"
    );
    transport[12] = 0xf0;
    assert_eq!(
        parse(&pcap(&ipv4(&transport, 6), true, false))
            .unwrap()
            .issues[0]
            .code,
        "tcp_header"
    );
}

#[test]
/// Header snapshot limits and any later fatal record invalidate earlier parsed observations.
fn fatal_after_valid_record() {
    let mut data = pcap(&udp(&[], 123), true, false);
    data.extend([0; 15]);
    assert_eq!(parse(&data).unwrap_err(), "record_truncated");
    let mut data = pcap(&udp(&[], 123), true, false);
    data[16..20].copy_from_slice(&65536u32.to_le_bytes());
    assert_eq!(parse(&data).unwrap_err(), "capture_snaplen");
    let mut data = pcap(&udp(&[], 123), true, false);
    data[32..36].copy_from_slice(&65536u32.to_le_bytes());
    assert_eq!(parse(&data).unwrap_err(), "record_length");
}

#[test]
/// TC loss, root labels, pointer hop cycles and unsupported opcode remain explicit.
fn dns_extended_boundaries() {
    let mut data = question();
    data[2] |= 2;
    assert_eq!(dns(&data).unwrap_err(), "dns_truncated_message");
    data[2] = 0x09;
    assert_eq!(dns(&data).unwrap_err(), "dns_unsupported");
    let mut root = vec![0; 12];
    root[5] = 1;
    root.extend([0, 0, 1, 0, 1]);
    assert_eq!(dns(&root).unwrap().name, "");
    let mut cycle = vec![0; 12];
    cycle.extend([1, b'a', 0xc0, 12]);
    assert_eq!(name(&cycle, 12).unwrap_err(), "dns_hop_limit");
    cycle[15] = 1;
    assert_eq!(name(&cycle, 12).unwrap_err(), "dns_pointer");
}
