//! Jason Stys: read one bounded regular capture file and emit safe versioned TSV metadata.
// BEGIN CODE MAP (generated; python scripts/code_map.py)
// parameter: fs — line 30
// parameter: io — line 31
// parameter: process — line 32
// fn: run — line 36
// binding: args — line 37
// field/parameter: args — line 37
// field/parameter: usage — line 39
// binding: before — line 41
// binding: file — line 45
// binding: metadata — line 46
// binding: data — line 50
// binding: capture — line 54
// binding: output — line 55
// loop binding: value — line 57
// binding: name — line 58
// binding: qtype — line 58
// binding: rcode — line 58
// binding: response — line 58
// parameter: u8 — line 61
// loop binding: issue — line 86
// fn: main — line 93
// parameter: ExitCode — line 98
// END CODE MAP
#![forbid(unsafe_code)]
use network_defense_analysis_lab::{MAX_BYTES, parse};
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process::ExitCode,
};

/// The CLI accepts exactly one explicit local path, no stdin/devices/network or shell evaluation.
fn run() -> Result<(), &'static str> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: packet-decoder LOCAL.pcap");
    }
    let before = std::fs::metadata(&args[1]).map_err(|_| "capture_metadata")?;
    if !before.is_file() || before.len() > MAX_BYTES as u64 {
        return Err("capture_file_limit");
    }
    let file = File::open(&args[1]).map_err(|_| "capture_open")?;
    let metadata = file.metadata().map_err(|_| "capture_metadata")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return Err("capture_file_limit");
    }
    let mut data = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| "capture_read")?;
    let capture = parse(&data)?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    writeln!(output, "NDAL\t1\t{}", capture.packets).map_err(|_| "output_write")?;
    for value in capture.observations {
        let (name, response, rcode, qtype) = match value.dns {
            Some(dns) => (
                dns.name,
                u8::from(dns.response).to_string(),
                dns.rcode.to_string(),
                dns.qtype.to_string(),
            ),
            None => ("-".into(), "-".into(), "-".into(), "-".into()),
        };
        writeln!(
            output,
            "O\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            value.packet,
            value.time_ns,
            value.src,
            value.dst,
            value.sport,
            value.dport,
            value.protocol,
            value.flags,
            value.bytes,
            name,
            response,
            rcode,
            qtype
        )
        .map_err(|_| "output_write")?;
    }
    for issue in capture.issues {
        writeln!(output, "I\t{}\t{}", issue.packet, issue.code).map_err(|_| "output_write")?;
    }
    output.flush().map_err(|_| "output_write")
}

/// Use exit 2 for invalid/inaccessible captures; diagnostics never echo payloads or paths.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            ExitCode::from(2)
        }
    }
}
