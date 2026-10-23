//! We need a function that decodes a DNS name that is encoded in the 'RFC1035
//! compression format' to the usual representation like "www.tweede.golf".
//!
//! A DNS name consists of parts separated by periods, e.g., the domain name
//! above has three parts: "www", "tweede", and "golf".
//!
//! In RFC1035 format, these parts are encoded by prefixing them with one byte
//! indicating the length, followed by the bytes that comprise the part. The
//! domain name itself is zero-terminated (i.e., an "empty part" signifies the
//! end of a domain name); the periods between parts are not encoded.
//!
//! So, for example, "mailcrab.tweedegolf.nl" can be encoded as:
//!
//! 0x08 mailcrab 0x0A tweedegolf 0x02 nl 0x00
//! or, in Rust's bytestring notation:
//!
//! b"\x08mailcrab\x0Atweedegolf\x02nl\0"
//!
//! There are some restrictions:
//! - The maximum size of a part is 63 bytes.
//! - The maximum size of a full domain name (including periods) is 255 bytes.
//! - A domain name cannot be empty.
//!
//! ASSIGNMENT 1: Ignore the `_backlog` argument for now, and implement this
//! functionality. The test case `simple` should now pass. This test case is
//! minimal so feel free to improve the test cases, or even add fuzzing, etc.
//!
//! Make a commit after this point.
//!
//! ---
//!
//! The RFC1035 compression format is used in the context of a larger packet
//! consisting of multiple domain names, where suffixes occur multiple times,
//! e.g. a packet could consist of "mailcrab.tweedegolf.nl",
//! "mail.tweedegolf.nl", "mattermost.tweedegolf.nl", etc.
//!
//! To avoid having to encode the same suffix multiple times, we can jump to an
//! earlier suffix in the packet.
//!
//! This is done by, in place of encoding a part, encoding a 14-bit absolute
//! index in two bytes. The first byte will have its two most significant bits
//! set to 1, followed by the 6 most significant bits of the 14-bit index. The
//! second byte will hold the 8 least significant bits of the index. Or in other
//! words, this index is encoded in big-endian format with the first byte
//! bitwise OR'ed with 0xC0.
//!
//! So for example, this set of records encodes for "tweedegolf.nl",
//! "mailcrab.tweedegolf.nl", "mail.tweedegolf.nl" and
//! "secret.mailcrab.tweedegolf.nl".
//!
//! b"\x0Atweedegolf\x02nl\0\x08mailcrab\xC0\x00\x04mail\xC0\x00\x06secret\xC0\x0F"
//!
//! E.g. "mailcrab.tweedegolf.nl" starts at index 15, where the part for
//! "mailcrab" is encoded, followed by a jump back to index 0, where
//! "tweedegolf" followed by "nl" is encoded. You can find "mail.tweedegolf.nl"
//! at index 26 and "secret.mailcrab.tweedegolf.nl" at index 33.
//!
//! ASSIGNMENT 2: Add this functionality to `decode_dns_name`. The first
//! argument is a slice pointing to the current DNS name to be decoded; the
//! second contains the entire packet. Of course, the first argument is expected
//! to be subslice of the second argument. The second test case should now pass.
//! Again, the test case is the bare minimum.
//!
//! Make a commit after this point.
//!
//! ---
//!
//! ASSIGNMENT 3 (optional): use "cargo fuzz" to test your implementation, did
//! you find any nice bugs?
//!
//! Make a commit after this point.
//!
//! ---
//!
//! Make nice commits.
//!
//! For a better(?) explanation read section 4.1.4 of RFC 1035: https://www.ietf.org/rfc/rfc1035.txt
//!
//! NOTE: You're only allowed to use the Rust standard library, ob-vi-ous-ly.

/// Maximum length of a label (one part of a name), in bytes.
///
/// Length bytes with either of the two most significant bits set do not
/// encode a label (see [`LABEL_TYPE_MASK`]), so this is also the largest
/// value a length byte can take.
const MAX_LABEL_LEN: usize = 0x3F;

/// Maximum length of a decoded name including the separating periods.
///
/// This follows the assignment text. Strictly speaking RFC 1035 limits the
/// *wire* representation (length bytes and terminator included) to 255
/// bytes, which amounts to 253 bytes in the dotted representation.
const MAX_NAME_LEN: usize = 255;

/// The two most significant bits of the first byte of a label determine its
/// type: `00` is an ordinary length-prefixed label, `11` is a compression
/// pointer and `01` / `10` are reserved.
const LABEL_TYPE_MASK: u8 = 0xC0;
const LABEL_TYPE_NORMAL: u8 = 0x00;
const LABEL_TYPE_POINTER: u8 = 0xC0;

/// Decodes a DNS name in RFC 1035 wire format into its dotted representation,
/// e.g. `b"\x06google\x03com\0"` becomes `b"google.com"`.
///
/// `input` is the slice at which the name starts and `backlog` is the packet
/// containing it. Compression pointers (RFC 1035 section 4.1.4) are resolved
/// against `backlog`, which requires `input` to be a subslice of `backlog`;
/// when it is not, names containing pointers are rejected. Any bytes following
/// the end of the name are ignored, so `input` may simply extend to the end of
/// the packet.
///
/// A pointer is only accepted when it refers to data *before* the portion of
/// the packet currently being decoded: before `input` for the first pointer,
/// and before the previous pointer's target for every subsequent one. This is
/// what RFC 1035 calls "a prior occurrence of the same name". It rules out
/// forward references and pointer loops, and guarantees termination because
/// every jump strictly lowers the position being decoded.
///
/// Returns `None` when the name is not well-formed: it is truncated, a label
/// is of a reserved type, a pointer cannot be followed, the name is empty, or
/// the decoded name would be longer than [`MAX_NAME_LEN`] bytes.
///
/// Label bytes are copied verbatim; no escaping is performed for labels that
/// themselves contain a period or other special characters.
pub fn decode_dns_name(input: &[u8], backlog: &[u8]) -> Option<Box<[u8]>> {
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = input;
    // Pointers may only refer to positions in `backlog` strictly below this
    // bound. It starts at the position of `input` within `backlog` (`None` if
    // `input` is not part of `backlog`) and moves down with every pointer
    // that is followed.
    let mut pointer_bound = backlog.subslice_range(input).map(|range| range.start);

    loop {
        let (&first, rest) = cursor.split_first()?;

        match first & LABEL_TYPE_MASK {
            LABEL_TYPE_NORMAL => {
                let len = usize::from(first);
                debug_assert!(len <= MAX_LABEL_LEN);

                if len == 0 {
                    // Zero-length label: end of the name.
                    return if out.is_empty() {
                        None
                    } else {
                        Some(out.into_boxed_slice())
                    };
                }

                let (label, rest) = rest.split_at_checked(len)?;

                let separator = usize::from(!out.is_empty());
                if out.len() + separator + len > MAX_NAME_LEN {
                    return None;
                }
                if separator == 1 {
                    out.push(b'.');
                }
                out.extend_from_slice(label);

                cursor = rest;
            }
            LABEL_TYPE_POINTER => {
                let (&second, _) = rest.split_first()?;
                let target = usize::from(u16::from_be_bytes([first & !LABEL_TYPE_MASK, second]));

                if target >= pointer_bound? {
                    return None;
                }
                // `target < pointer_bound <= backlog.len()`, so this cannot
                // fail; `get` merely avoids a panicking index.
                cursor = backlog.get(target..)?;
                pointer_bound = Some(target);
            }
            _ => {
                // Reserved label types (RFC 1035 section 4.1.4).
                return None;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    /// Convenience wrapper: decode and unwrap into a `Vec` for comparisons.
    fn decode(input: &[u8], backlog: &[u8]) -> Option<Vec<u8>> {
        decode_dns_name(input, backlog).map(Vec::from)
    }

    /// Encodes `labels` in wire format (no compression).
    fn encode(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    /// Appends `labels` to `packet`, replacing the longest suffix that was
    /// written before (according to `suffixes`) by a compression pointer.
    /// Newly written suffixes are recorded in `suffixes`. Returns the offset
    /// at which the name starts.
    fn encode_compressed(
        packet: &mut Vec<u8>,
        labels: &[&[u8]],
        suffixes: &mut HashMap<Vec<Vec<u8>>, usize>,
    ) -> usize {
        let start = packet.len();
        for (i, label) in labels.iter().enumerate() {
            let suffix: Vec<Vec<u8>> = labels[i..].iter().map(|l| l.to_vec()).collect();
            if let Some(&offset) = suffixes.get(&suffix) {
                let pointer = u16::try_from(offset).unwrap() | 0xC000;
                packet.extend_from_slice(&pointer.to_be_bytes());
                return start;
            }
            if packet.len() <= 0x3FFF {
                suffixes.insert(suffix, packet.len());
            }
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label);
        }
        packet.push(0);
        start
    }

    #[test]
    fn simple() {
        let input = b"\x06google\x03com\0";

        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref().unwrap(),
            b"google.com"
        );
    }

    #[test]
    fn readme_example() {
        assert_eq!(
            decode(b"\x08mailcrab\x0Atweedegolf\x02nl\0", &[]).unwrap(),
            b"mailcrab.tweedegolf.nl"
        );
    }

    #[test]
    fn single_label() {
        assert_eq!(decode(b"\x09localhost\0", &[]).unwrap(), b"localhost");
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        assert_eq!(
            decode(b"\x03www\x03foo\0\x03bar\0garbage", &[]).unwrap(),
            b"www.foo"
        );
    }

    #[test]
    fn arbitrary_label_bytes_are_copied_verbatim() {
        assert_eq!(
            decode(b"\x04\x00\xFF\x2E\x20\x02ok\0", &[]).unwrap(),
            b"\x00\xFF\x2E\x20.ok"
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(decode(b"", &[]), None);
    }

    #[test]
    fn empty_name() {
        assert_eq!(decode(b"\0", &[]), None);
        assert_eq!(decode(b"\0\x03www\0", &[]), None);
    }

    #[test]
    fn missing_terminator() {
        assert_eq!(decode(b"\x03www", &[]), None);
        assert_eq!(decode(b"\x03www\x03foo", &[]), None);
    }

    #[test]
    fn truncated_label() {
        assert_eq!(decode(b"\x03ww", &[]), None);
        assert_eq!(decode(b"\x03www\x05foo\0", &[]), None);
        assert_eq!(decode(b"\x3F", &[]), None);
    }

    #[test]
    fn reserved_label_types() {
        // 0b01xxxxxx and 0b10xxxxxx are reserved.
        assert_eq!(decode(b"\x40abc\0", &[]), None);
        assert_eq!(decode(b"\x7Fabc\0", &[]), None);
        assert_eq!(decode(b"\x80abc\0", &[]), None);
        assert_eq!(decode(b"\xBFabc\0", &[]), None);
        assert_eq!(decode(b"\x03www\x41abc\0", &[]), None);
    }

    #[test]
    fn label_of_maximum_length() {
        let label = [b'a'; MAX_LABEL_LEN];
        assert_eq!(decode(&encode(&[&label]), &[]).unwrap(), label);
    }

    #[test]
    fn name_of_maximum_length() {
        // 4 labels of 63 bytes with 3 periods: 255 bytes.
        let long = [b'a'; 63];
        let labels: [&[u8]; 4] = [&long, &long, &long, &long];
        let decoded = decode(&encode(&labels), &[]).unwrap();
        assert_eq!(decoded.len(), MAX_NAME_LEN);
        assert_eq!(decoded, labels.join(&b'.'));
    }

    #[test]
    fn name_too_long() {
        // 63 + 63 + 63 + 62 + 1 bytes of labels with 4 periods: 256 bytes.
        let long = [b'a'; 63];
        let short = [b'b'; 62];
        let single = [b'c'; 1];
        let labels: [&[u8]; 5] = [&long, &long, &long, &short, &single];
        assert_eq!(decode(&encode(&labels), &[]), None);

        // Exactly 255 bytes of labels, but the periods push it over the limit.
        let labels: [&[u8]; 5] = [&long, &long, &long, &long, &long];
        assert_eq!(decode(&encode(&labels), &[]), None);
    }

    #[test]
    fn round_trip() {
        let names: &[&[&[u8]]] = &[
            &[b"www", b"tweede", b"golf"],
            &[b"a"],
            &[b"a", b"b", b"c", b"d", b"e", b"f"],
            &[b"xn--bcher-kva", b"example"],
            &[b"_sip", b"_tcp", b"example", b"com"],
        ];
        for labels in names {
            assert_eq!(decode(&encode(labels), &[]).unwrap(), labels.join(&b'.'));
        }
    }

    /// Minimal deterministic PRNG so the pseudo-fuzz test below needs no
    /// dependencies and is reproducible.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Checks the invariants that must hold for any successful decode.
    fn check_invariants(input: &[u8], output: &[u8]) {
        assert!(!output.is_empty(), "empty name decoded from {input:?}");
        assert!(output.len() <= MAX_NAME_LEN, "name too long for {input:?}");
        assert!(output.len() <= input.len(), "output longer than input");
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let mut buf = Vec::new();
        for _ in 0..20_000 {
            let len = rng.below(300);
            buf.clear();
            for _ in 0..len {
                // Bias towards small values so that names are often valid.
                let b = match rng.below(4) {
                    0 => rng.below(256) as u8,
                    1 => 0,
                    _ => rng.below(8) as u8,
                };
                buf.push(b);
            }
            if let Some(output) = decode(&buf, &[]) {
                check_invariants(&buf, &output);
            }
        }
    }

    #[test]
    fn random_valid_names_round_trip() {
        let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
        for _ in 0..5_000 {
            let label_count = 1 + rng.below(8);
            let labels: Vec<Vec<u8>> = (0..label_count)
                .map(|_| {
                    let len = 1 + rng.below(MAX_LABEL_LEN);
                    (0..len).map(|_| rng.below(256) as u8).collect()
                })
                .collect();
            let refs: Vec<&[u8]> = labels.iter().map(Vec::as_slice).collect();
            let expected = refs.join(&b'.');
            let encoded = encode(&refs);

            let decoded = decode(&encoded, &[]);
            if expected.len() <= MAX_NAME_LEN {
                assert_eq!(decoded.unwrap(), expected);
            } else {
                assert_eq!(decoded, None);
            }
        }
    }

    #[test]
    fn simple_backref() {
        let pkt = b"\x06google\x03com\0\x03www\xC0\x00";

        assert_eq!(
            decode_dns_name(&pkt[12..], &pkt[..]).as_deref().unwrap(),
            b"www.google.com"
        );
    }

    const README_PACKET: &[u8] =
        b"\x0Atweedegolf\x02nl\0\x08mailcrab\xC0\x00\x04mail\xC0\x00\x06secret\xC0\x0F";

    #[test]
    fn readme_packet() {
        let pkt = README_PACKET;
        assert_eq!(decode(&pkt[0..], pkt).unwrap(), b"tweedegolf.nl");
        assert_eq!(decode(&pkt[15..], pkt).unwrap(), b"mailcrab.tweedegolf.nl");
        assert_eq!(decode(&pkt[26..], pkt).unwrap(), b"mail.tweedegolf.nl");
        // Follows a chain of two pointers.
        assert_eq!(
            decode(&pkt[33..], pkt).unwrap(),
            b"secret.mailcrab.tweedegolf.nl"
        );
    }

    #[test]
    fn name_consisting_of_only_a_pointer() {
        let mut pkt = README_PACKET.to_vec();
        pkt.extend_from_slice(b"\xC0\x0F");
        let start = pkt.len() - 2;
        assert_eq!(
            decode(&pkt[start..], &pkt).unwrap(),
            b"mailcrab.tweedegolf.nl"
        );
    }

    #[test]
    fn pointer_to_terminator() {
        let pkt = b"\x03com\0\x03www\xC0\x04\xC0\x04";
        assert_eq!(decode(&pkt[5..], pkt).unwrap(), b"www");
        // A name made up of a pointer to a terminator only is empty.
        assert_eq!(decode(&pkt[11..], pkt), None);
    }

    #[test]
    fn pointer_uses_all_fourteen_bits() {
        // Put the referenced name beyond offset 255 so that the high bits of
        // the pointer matter.
        let mut pkt = vec![0u8; 300];
        pkt.extend_from_slice(b"\x03com\0");
        let start = pkt.len();
        pkt.extend_from_slice(b"\x03www\xC1\x2C"); // 0x012C == 300
        assert_eq!(decode(&pkt[start..], &pkt).unwrap(), b"www.com");
    }

    #[test]
    fn truncated_pointer() {
        let pkt = b"\x03com\0\x03www\xC0";
        assert_eq!(decode(&pkt[5..], pkt), None);
    }

    #[test]
    fn pointer_without_packet() {
        let name = b"\x03www\xC0\x00";
        assert_eq!(decode(name, &[]), None);
        // The packet does not contain `input`, so there is nothing to
        // resolve the pointer against.
        assert_eq!(decode(name, b"\x03com\0"), None);
    }

    #[test]
    fn pointer_beyond_packet() {
        let pkt = b"\x03com\0\x03www\xC0\x20\x03www\xFF\xFF";
        assert_eq!(decode(&pkt[5..], pkt), None);
        assert_eq!(decode(&pkt[11..], pkt), None);
    }

    #[test]
    fn forward_pointer() {
        // A lenient decoder would produce "www.com"; RFC 1035 only allows
        // pointers to prior occurrences.
        let pkt = b"\x03aaa\0\x03www\xC0\x0B\x03com\0";
        assert_eq!(decode(&pkt[5..], pkt), None);
        assert_eq!(decode(&pkt[11..], pkt).unwrap(), b"com");
    }

    #[test]
    fn pointer_to_itself() {
        let pkt = b"\x03www\xC0\x04";
        assert_eq!(decode(&pkt[0..], pkt), None);
        assert_eq!(decode(&pkt[4..], pkt), None);
    }

    #[test]
    fn pointer_into_current_name() {
        // Pointer back to the start of the name it is part of.
        let pkt = b"\x03www\xC0\x00";
        assert_eq!(decode(&pkt[0..], pkt), None);
    }

    #[test]
    fn pointer_loop_through_earlier_label() {
        // Decoding from offset 2 jumps back to 0, reads "a" and arrives at
        // the same pointer again. The pointer does point backwards, so a
        // decoder that only checks that would loop forever.
        let pkt = b"\x01a\xC0\x00";
        assert_eq!(decode(&pkt[2..], pkt), None);
    }

    #[test]
    fn mutually_referencing_pointers() {
        let pkt = b"\xC0\x02\xC0\x00";
        assert_eq!(decode(&pkt[0..], pkt), None);
        assert_eq!(decode(&pkt[2..], pkt), None);
    }

    #[test]
    fn pointer_into_middle_of_label() {
        // Pointers into the middle of a label cannot be detected without
        // parsing the whole packet; whatever is found there is decoded.
        let pkt = b"\x02\x01a\0\xC0\x01";
        assert_eq!(decode(&pkt[0..], pkt).unwrap(), b"\x01a");
        assert_eq!(decode(&pkt[4..], pkt).unwrap(), b"a");
    }

    #[test]
    fn name_length_limit_spans_pointers() {
        let long = [b'a'; 63];

        // 191 bytes at offset 0, then 63 + 1 + 191 == 255 bytes: fine.
        let mut pkt = encode(&[&long, &long, &long]);
        let start = pkt.len();
        pkt.push(63);
        pkt.extend_from_slice(&long);
        pkt.extend_from_slice(b"\xC0\x00");
        assert_eq!(decode(&pkt[start..], &pkt).unwrap().len(), MAX_NAME_LEN);

        // 255 bytes at offset 0, then 1 + 1 + 255 == 257 bytes: too long.
        let mut pkt = encode(&[&long, &long, &long, &long]);
        let start = pkt.len();
        pkt.extend_from_slice(b"\x01b\xC0\x00");
        assert_eq!(decode(&pkt[start..], &pkt), None);
    }

    #[test]
    fn random_compressed_packets_round_trip() {
        const POOL: &[&[u8]] = &[
            b"a",
            b"bb",
            b"www",
            b"mail",
            b"mailcrab",
            b"tweedegolf",
            b"golf",
            b"nl",
            b"com",
            b"example",
            b"secret",
            b"xn--bcher-kva",
        ];
        let mut rng = XorShift(0x2545_F491_4F6C_DD1D);

        for _ in 0..500 {
            let mut packet = Vec::new();
            let mut suffixes = HashMap::new();
            let mut names: Vec<(usize, Vec<u8>)> = Vec::new();

            for _ in 0..1 + rng.below(40) {
                // Some unrelated bytes between names, like a real packet has.
                for _ in 0..rng.below(6) {
                    packet.push(rng.below(256) as u8);
                }

                let label_count = 1 + rng.below(8);
                let labels: Vec<Vec<u8>> = (0..label_count)
                    .map(|_| {
                        if rng.below(4) == 0 {
                            (0..1 + rng.below(20))
                                .map(|_| rng.below(256) as u8)
                                .collect()
                        } else {
                            POOL[rng.below(POOL.len())].to_vec()
                        }
                    })
                    .collect();
                let refs: Vec<&[u8]> = labels.iter().map(Vec::as_slice).collect();

                let start = encode_compressed(&mut packet, &refs, &mut suffixes);
                names.push((start, refs.join(&b'.')));
            }

            for (start, expected) in &names {
                assert_eq!(
                    decode(&packet[*start..], &packet).as_ref(),
                    Some(expected),
                    "packet {packet:?} at offset {start}"
                );
            }
        }
    }

    #[test]
    fn random_packets_never_panic() {
        let mut rng = XorShift(0x0123_4567_89AB_CDEF);
        let mut packet = Vec::new();
        for _ in 0..20_000 {
            let len = 1 + rng.below(400);
            packet.clear();
            for _ in 0..len {
                let b = match rng.below(6) {
                    0 => rng.below(256) as u8,
                    1 => 0,
                    2 => 0xC0 | rng.below(2) as u8,
                    _ => rng.below(8) as u8,
                };
                packet.push(b);
            }
            let start = rng.below(packet.len());
            if let Some(output) = decode(&packet[start..], &packet) {
                assert!(!output.is_empty());
                assert!(output.len() <= MAX_NAME_LEN);
            }
        }
    }
}
