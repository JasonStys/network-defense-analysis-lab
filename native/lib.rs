//! Jason Stys: bounded classic-PCAP/Ethernet/IPv4/UDP/TCP/DNS metadata decoder.
//! Never opens a socket; returned issues preserve unsupported/truncated evidence explicitly.
// BEGIN CODE MAP (generated; python scripts/code_map.py)
// const: MAX_BYTES — line 142
// field/parameter: _BYTES — line 142
// const: MAX_PACKETS — line 144
// field/parameter: _PACKETS — line 144
// struct: Observation — line 148
// field/parameter: packet — line 149
// field/parameter: time_ns — line 150
// field/parameter: src — line 151
// field/parameter: dst — line 152
// field/parameter: sport — line 153
// field/parameter: dport — line 154
// field/parameter: protocol — line 155
// field/parameter: flags — line 156
// field/parameter: bytes — line 157
// field/parameter: dns — line 158
// struct: Dns — line 163
// field/parameter: name — line 164
// field/parameter: response — line 165
// field/parameter: rcode — line 166
// field/parameter: qtype — line 167
// struct: Issue — line 172
// field/parameter: packet — line 173
// field/parameter: code — line 174
// struct: Capture — line 179
// field/parameter: packets — line 180
// field/parameter: observations — line 181
// field/parameter: issues — line 182
// field/parameter: data — line 186
// field/parameter: offset — line 186
// fn: word — line 186
// binding: bytes — line 187
// field/parameter: data — line 194
// field/parameter: little — line 194
// field/parameter: offset — line 194
// fn: number — line 194
// binding: bytes — line 195
// parameter: u32 — line 201
// parameter: u32 — line 203
// field/parameter: parts — line 208
// fn: checksum — line 208
// binding: sum — line 209
// field/parameter: sum — line 209
// binding: high — line 210
// loop binding: part — line 211
// loop binding: byte — line 212
// binding: first — line 213
// binding: first — line 221
// field/parameter: data — line 231
// field/parameter: start — line 231
// fn: name — line 231
// binding: pos — line 232
// binding: consumed — line 233
// binding: labels — line 234
// binding: expanded — line 235
// loop binding: _ — line 236
// binding: length — line 237
// binding: pointer — line 242
// binding: size — line 253
// binding: label — line 254
// field/parameter: data — line 273
// fn: dns — line 273
// binding: flags — line 277
// binding: pos — line 284
// binding: question — line 284
// binding: qtype — line 285
// binding: count — line 290
// parameter: usize — line 291
// loop binding: _ — line 295
// binding: _ — line 296
// binding: next — line 296
// binding: size — line 298
// field/parameter: name — line 308
// parameter: name — line 308
// field/parameter: response — line 309
// parameter: response — line 309
// parameter: rcode — line 310
// field/parameter: bytes — line 316
// fn: address — line 316
// fn: frame — line 321
// field/parameter: data — line 322
// parameter: data — line 322
// field/parameter: packet — line 323
// parameter: packet — line 323
// field/parameter: time_ns — line 324
// parameter: time_ns — line 324
// binding: ip — line 332
// binding: header — line 336
// binding: total — line 340
// binding: transport — line 353
// binding: protocol — line 354
// binding: pseudo — line 355
// binding: flags — line 361
// binding: kind — line 361
// binding: payload — line 361
// binding: size — line 378
// binding: sport — line 389
// binding: dport — line 390
// binding: issue — line 391
// binding: decoded — line 392
// field/parameter: src — line 412
// parameter: src — line 412
// field/parameter: dst — line 413
// parameter: dst — line 413
// field/parameter: protocol — line 416
// parameter: protocol — line 416
// field/parameter: bytes — line 418
// parameter: bytes — line 418
// field/parameter: dns — line 419
// parameter: dns — line 419
// field/parameter: data — line 426
// fn: parse — line 426
// binding: little — line 433
// binding: nano — line 433
// binding: snaplen — line 443
// binding: result — line 450
// parameter: packets — line 451
// field/parameter: observations — line 452
// parameter: observations — line 452
// field/parameter: issues — line 453
// parameter: issues — line 453
// binding: pos — line 455
// binding: last — line 456
// binding: header — line 461
// binding: seconds — line 464
// binding: fraction — line 465
// binding: time_ns — line 469
// binding: captured — line 470
// binding: original — line 471
// binding: packet_data — line 476
// binding: packet — line 481
// parameter: code — line 485
// parameter: code — line 492
// binding: code — line 499
// mod: tests — line 510
// END CODE MAP
#![forbid(unsafe_code)]

/// Hard byte cap; protects allocation before any parsing work.
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
/// Maximum packet records; bounds output and downstream work.
pub const MAX_PACKETS: usize = 20_000;

/// Safe metadata only; strings cannot contain TSV controls or application payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub packet: usize,
    pub time_ns: u64,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub protocol: &'static str,
    pub flags: u8,
    pub bytes: usize,
    pub dns: Option<Dns>,
}

/// One validated DNS question; answers are structurally checked, not interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    pub name: String,
    pub response: bool,
    pub rcode: u8,
    pub qtype: u16,
}

/// A packet-level issue is not silently conflated with a clean capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub packet: usize,
    pub code: &'static str,
}

/// Complete validated capture: fatal container errors never return partial results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub packets: usize,
    pub observations: Vec<Observation>,
    pub issues: Vec<Issue>,
}

/// Read a checked two-byte network-order value; offset is never trusted.
fn word(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    let bytes = data
        .get(offset..offset.saturating_add(2))
        .ok_or("truncated")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Read a checked PCAP u32 in the capture's byte order.
fn number(data: &[u8], offset: usize, little: bool) -> Result<u32, &'static str> {
    let bytes: [u8; 4] = data
        .get(offset..offset.saturating_add(4))
        .ok_or("truncated")?
        .try_into()
        .map_err(|_| "truncated")?;
    Ok(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// Internet checksum across byte slices, preserving odd-length segment boundaries.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut high = None;
    for part in parts {
        for byte in *part {
            if let Some(first) = high.take() {
                sum += u32::from(u16::from_be_bytes([first, *byte]));
                sum = (sum & 0xffff) + (sum >> 16);
            } else {
                high = Some(*byte);
            }
        }
    }
    if let Some(first) = high {
        sum += u32::from(first) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Decode a bounded DNS hostname with backward-only compression and cycle/size checks.
fn name(data: &[u8], start: usize) -> Result<(String, usize), &'static str> {
    let mut pos = start;
    let mut consumed = None;
    let mut labels = Vec::new();
    let mut expanded = 1;
    for _ in 0..128 {
        let length = *data.get(pos).ok_or("dns_truncated")?;
        if length == 0 {
            return Ok((labels.join("."), consumed.unwrap_or(pos + 1)));
        }
        if length & 0xc0 == 0xc0 {
            let pointer = usize::from(word(data, pos).map_err(|_| "dns_truncated")? & 0x3fff);
            if pointer < 12 || pointer >= pos {
                return Err("dns_pointer");
            }
            consumed.get_or_insert(pos + 2);
            pos = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("dns_label");
        }
        let size = usize::from(length);
        let label = data.get(pos + 1..pos + 1 + size).ok_or("dns_truncated")?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return Err("dns_label");
        }
        expanded += size + 1;
        if expanded > 255 {
            return Err("dns_name_limit");
        }
        // Hostname ASCII restriction intentionally rejects arbitrary binary DNS labels.
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += size + 1;
    }
    Err("dns_hop_limit")
}

/// Validate a single-question DNS message, all record envelopes and trailing bytes.
pub fn dns(data: &[u8]) -> Result<Dns, &'static str> {
    if data.len() < 12 {
        return Err("dns_truncated");
    }
    let flags = word(data, 2)?;
    if flags & 0x0200 != 0 {
        return Err("dns_truncated_message");
    }
    if flags & 0x7800 != 0 || word(data, 4)? != 1 {
        return Err("dns_unsupported");
    }
    let (question, mut pos) = name(data, 12)?;
    let qtype = word(data, pos).map_err(|_| "dns_truncated")?;
    if word(data, pos + 2).map_err(|_| "dns_truncated")? != 1 {
        return Err("dns_unsupported");
    }
    pos += 4;
    let count =
        usize::from(word(data, 6)?) + usize::from(word(data, 8)?) + usize::from(word(data, 10)?);
    if count > 128 {
        return Err("dns_record_limit");
    }
    for _ in 0..count {
        let (_, next) = name(data, pos)?;
        pos = next;
        let size = usize::from(word(data, pos + 8).map_err(|_| "dns_truncated")?);
        pos = pos.checked_add(10 + size).ok_or("dns_truncated")?;
        if pos > data.len() {
            return Err("dns_truncated");
        }
    }
    if pos != data.len() {
        return Err("dns_trailing");
    }
    Ok(Dns {
        name: question,
        response: flags & 0x8000 != 0,
        rcode: (flags & 15) as u8,
        qtype,
    })
}

/// Render exactly four checked IPv4 bytes without doing reverse DNS lookups.
fn address(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Decode one complete Ethernet frame; reject fragments/checksums, retain DNS limitations.
fn frame(
    data: &[u8],
    packet: usize,
    time_ns: u64,
) -> Result<(Observation, Option<&'static str>), &'static str> {
    if data.len() < 14 {
        return Err("ethernet_truncated");
    }
    if word(data, 12)? != 0x0800 {
        return Err("unsupported_ethertype");
    }
    let ip = &data[14..];
    if ip.len() < 20 {
        return Err("ipv4_truncated");
    }
    let header = usize::from(ip[0] & 15) * 4;
    if ip[0] >> 4 != 4 || header < 20 || header > ip.len() {
        return Err("ipv4_header");
    }
    let total = usize::from(word(ip, 2)?);
    if total < header || total > ip.len() {
        return Err("ipv4_length");
    }
    if checksum(&[&ip[..header]]) != 0 {
        return Err("ipv4_checksum");
    }
    if word(ip, 6)? & 0x8000 != 0 {
        return Err("ipv4_reserved_flag");
    }
    if word(ip, 6)? & 0x3fff != 0 {
        return Err("unsupported_fragment");
    }
    let transport = &ip[header..total];
    let protocol = ip[9];
    let pseudo = [
        0,
        protocol,
        (transport.len() >> 8) as u8,
        transport.len() as u8,
    ];
    let (kind, flags, payload) = match protocol {
        17 => {
            if transport.len() < 8 {
                return Err("udp_truncated");
            }
            if usize::from(word(transport, 4)?) != transport.len() {
                return Err("udp_length");
            }
            if word(transport, 6)? != 0 && checksum(&[&ip[12..20], &pseudo, transport]) != 0 {
                return Err("udp_checksum");
            }
            ("udp", 0, &transport[8..])
        }
        6 => {
            if transport.len() < 20 {
                return Err("tcp_truncated");
            }
            let size = usize::from(transport[12] >> 4) * 4;
            if size < 20 || size > transport.len() {
                return Err("tcp_header");
            }
            if checksum(&[&ip[12..20], &pseudo, transport]) != 0 {
                return Err("tcp_checksum");
            }
            ("tcp", transport[13], &transport[size..])
        }
        _ => return Err("unsupported_transport"),
    };
    let sport = word(transport, 0)?;
    let dport = word(transport, 2)?;
    let mut issue = None;
    let decoded = if sport == 53 || dport == 53 {
        if kind == "tcp" {
            issue = Some("unsupported_dns_tcp");
            None
        } else {
            match dns(payload) {
                Ok(value) => Some(value),
                Err(code) => {
                    issue = Some(code);
                    None
                }
            }
        }
    } else {
        None
    };
    Ok((
        Observation {
            packet,
            time_ns,
            src: address(&ip[12..16]),
            dst: address(&ip[16..20]),
            sport,
            dport,
            protocol: kind,
            flags,
            bytes: total,
            dns: decoded,
        },
        issue,
    ))
}

/// Parse a bounded complete classic PCAP (four endian/time magics), never accept PCAPNG.
pub fn parse(data: &[u8]) -> Result<Capture, &'static str> {
    if data.len() > MAX_BYTES {
        return Err("capture_byte_limit");
    }
    if data.len() < 24 {
        return Err("capture_truncated");
    }
    let (little, nano) = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("unsupported_capture"),
    };
    if number(data, 4, little)? != if little { 0x0004_0002 } else { 0x0002_0004 } {
        return Err("capture_version");
    }
    let snaplen = number(data, 16, little)? as usize;
    if snaplen == 0 || snaplen > 65535 {
        return Err("capture_snaplen");
    }
    if number(data, 20, little)? != 1 {
        return Err("unsupported_linktype");
    }
    let mut result = Capture {
        packets: 0,
        observations: Vec::new(),
        issues: Vec::new(),
    };
    let mut pos = 24;
    let mut last = 0;
    while pos < data.len() {
        if result.packets >= MAX_PACKETS {
            return Err("capture_packet_limit");
        }
        let header = data
            .get(pos..pos.saturating_add(16))
            .ok_or("record_truncated")?;
        let seconds = u64::from(number(header, 0, little)?);
        let fraction = u64::from(number(header, 4, little)?);
        if fraction >= if nano { 1_000_000_000 } else { 1_000_000 } {
            return Err("capture_timestamp");
        }
        let time_ns = seconds * 1_000_000_000 + fraction * if nano { 1 } else { 1000 };
        let captured = number(header, 8, little)? as usize;
        let original = number(header, 12, little)? as usize;
        if captured > snaplen || captured > original {
            return Err("record_length");
        }
        pos += 16;
        let packet_data = data
            .get(pos..pos.saturating_add(captured))
            .ok_or("record_truncated")?;
        pos += captured;
        result.packets += 1;
        let packet = result.packets;
        if time_ns < last {
            result.issues.push(Issue {
                packet,
                code: "timestamp_reordered",
            });
        }
        last = time_ns;
        if captured < original {
            result.issues.push(Issue {
                packet,
                code: "capture_packet_truncated",
            });
            continue;
        }
        match frame(packet_data, packet, time_ns) {
            Ok((observation, issue)) => {
                result.observations.push(observation);
                if let Some(code) = issue {
                    result.issues.push(Issue { packet, code });
                }
            }
            Err(code) => result.issues.push(Issue { packet, code }),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
