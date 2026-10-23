//! Feeds arbitrary packets to the decoder and checks that it never panics,
//! never hangs and only returns names that satisfy the documented limits.
//!
//! The first two bytes of the fuzz input select the offset at which decoding
//! starts; the remainder is the packet.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((offset_bytes, packet)) = data.split_first_chunk::<2>() else {
        return;
    };
    let offset = usize::from(u16::from_be_bytes(*offset_bytes)) % (packet.len() + 1);

    if let Some(name) = dns_challenge::decode_dns_name(&packet[offset..], packet) {
        assert!(!name.is_empty(), "decoded an empty name");
        assert!(name.len() <= 255, "decoded a name of {} bytes", name.len());
        // Labels are copied verbatim and may themselves contain periods, so
        // the dotted structure can only be checked when the packet has none.
        if !packet.contains(&b'.') {
            assert!(!name.starts_with(b"."), "decoded name starts with a period");
            assert!(!name.ends_with(b"."), "decoded name ends with a period");
            assert!(
                !name.windows(2).any(|w| w == b".."),
                "decoded name has an empty label"
            );
        }
    }
});
