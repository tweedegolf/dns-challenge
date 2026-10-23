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
/// `input` is the slice at which the name starts. Any bytes following the
/// terminating zero-length label are ignored, so `input` may simply extend to
/// the end of the packet. `_backlog` is currently unused.
///
/// Returns `None` when `input` does not hold a well-formed name: it is
/// truncated, a label is of a reserved type, the name is empty, or the decoded
/// name would be longer than [`MAX_NAME_LEN`] bytes.
///
/// Label bytes are copied verbatim; no escaping is performed for labels that
/// themselves contain a period or other special characters.
pub fn decode_dns_name(input: &[u8], _backlog: &[u8]) -> Option<Box<[u8]>> {
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = input;

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
                // Compression pointers are not supported (yet).
                return None;
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
}
