//! Builds a packet of names from structured fuzz input, compressing shared
//! suffixes with pointers, and checks that every name decodes to exactly what
//! was encoded.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const MAX_POINTER: usize = 0x3FFF;

/// Appends `labels` to `packet`, replacing the longest suffix that was written
/// before by a compression pointer. Returns the offset of the name.
fn encode_compressed(
    packet: &mut Vec<u8>,
    labels: &[Vec<u8>],
    suffixes: &mut HashMap<Vec<Vec<u8>>, usize>,
) -> usize {
    let start = packet.len();
    for (i, label) in labels.iter().enumerate() {
        let suffix = labels[i..].to_vec();
        if let Some(&offset) = suffixes.get(&suffix) {
            let pointer = u16::try_from(offset).unwrap() | 0xC000;
            packet.extend_from_slice(&pointer.to_be_bytes());
            return start;
        }
        if packet.len() <= MAX_POINTER {
            suffixes.insert(suffix, packet.len());
        }
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label);
    }
    packet.push(0);
    start
}

/// Turns arbitrary fuzz input into a valid name: labels are capped at 63
/// bytes, empty labels are dropped and the name is cut off at 255 bytes.
fn sanitize(mut labels: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    labels.retain(|label| !label.is_empty());
    for label in &mut labels {
        label.truncate(MAX_LABEL_LEN);
    }
    let mut dotted_len = 0;
    let keep = labels
        .iter()
        .take_while(|label| {
            dotted_len += label.len() + usize::from(dotted_len > 0);
            dotted_len <= MAX_NAME_LEN
        })
        .count();
    labels.truncate(keep);
    labels
}

fuzz_target!(|names: Vec<Vec<Vec<u8>>>| {
    let mut packet = Vec::new();
    let mut suffixes = HashMap::new();
    let mut expected = Vec::new();

    for labels in names {
        let labels = sanitize(labels);
        if labels.is_empty() {
            continue;
        }
        let start = encode_compressed(&mut packet, &labels, &mut suffixes);
        expected.push((start, labels.join(&b'.')));
    }

    for (start, name) in expected {
        let decoded = dns_challenge::decode_dns_name(&packet[start..], &packet);
        assert_eq!(
            decoded.as_deref(),
            Some(name.as_slice()),
            "packet {packet:?} at offset {start}"
        );
    }
});
