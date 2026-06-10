//! Fuzz the wire-format parser: arbitrary bytes must parse or be rejected
//! without panicking, and `peek` must agree with `parse` about validity.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::message;

fuzz_target!(|data: &[u8]| {
    let parsed = message::parse(data);
    let peeked = message::peek(data);
    assert_eq!(parsed.is_ok(), peeked.is_ok());
    if let Ok(packet) = parsed {
        // Exercise the typed views (forces all field slicing).
        let _ = format!("{packet:?}");
    }
    let _ = message::ip_packet_len(data);
});
