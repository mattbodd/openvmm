// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming-bounded decryptor: walk an encrypted serial capture
//! buffer, find each ``[[OHENC v1 ...]]`` sentinel, decrypt the
//! record, and write the recovered plaintext (interleaved with
//! verbatim plaintext bytes from outside the records) to an output
//! sink.

use anyhow::Context;
use anyhow::bail;
use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::format::SentinelMatch;
use openhcl_serial_console_crypto::format::find_next_sentinel;
use openhcl_serial_console_crypto::gks::ParsedGks;
use std::collections::HashMap;
use std::io::Write;

/// Stats reported by [`run`] about a single decryption pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct DecryptStats {
    /// Number of records that decrypted successfully.
    pub records_ok: usize,
    /// Number of records that failed to decrypt or parse. In strict
    /// mode this is at most 1 because the run aborts on the first
    /// failure.
    pub records_failed: usize,
    /// Number of distinct sessions observed in successfully
    /// authenticated records.
    pub sessions_observed: usize,
}

/// Run the decryptor over `input`, writing recovered plaintext (and
/// any passthrough plaintext from outside records) to `output`.
///
/// In default mode, malformed sentinels are passed through verbatim
/// (so a stray ``[[OHENC `` in plaintext does not silently disappear)
/// and decryption / parse failures are reported with a
/// ``<<decrypt failed offset=N reason=...>>`` marker injected into
/// the output stream. In `strict` mode, the first malformed sentinel
/// or decryption failure is fatal.
pub fn run(
    input: &[u8],
    output: &mut impl Write,
    gks: &ParsedGks,
    strict: bool,
) -> anyhow::Result<DecryptStats> {
    let mut state = SessionState::new();
    let mut stats = DecryptStats::default();
    let mut cursor = 0;

    while cursor <= input.len() {
        match find_next_sentinel(input, cursor) {
            SentinelMatch::NotFound => {
                output
                    .write_all(&input[cursor..])
                    .context("writing trailing plaintext")?;
                break;
            }
            SentinelMatch::Found {
                start,
                end,
                payload,
            } => {
                output
                    .write_all(&input[cursor..start])
                    .context("writing leading plaintext before record")?;
                match Record::parse_payload(&payload) {
                    Ok(record) => match try_decrypt(gks, &record, &mut state) {
                        Ok(plaintext) => {
                            output
                                .write_all(&plaintext)
                                .context("writing decrypted record")?;
                            stats.records_ok += 1;
                        }
                        Err(err) => {
                            stats.records_failed += 1;
                            handle_failure(strict, output, start, &err.to_string())?;
                        }
                    },
                    Err(err) => {
                        stats.records_failed += 1;
                        handle_failure(strict, output, start, &err.to_string())?;
                    }
                }
                cursor = end;
            }
            SentinelMatch::Malformed { start, reason } => {
                if strict {
                    bail!("malformed encrypted-serial sentinel at offset {start}: {reason}");
                }
                tracing::warn!(
                    offset = start,
                    %reason,
                    "skipping malformed encrypted-serial sentinel; bytes will be passed through verbatim",
                );
                // Pass everything up to and including the opening
                // bracket through, then resume scanning right after
                // it. This way the output preserves a record of the
                // candidate bytes the producer emitted.
                let pass_end = (start + 1).min(input.len());
                output
                    .write_all(&input[cursor..pass_end])
                    .context("passing through leading bytes of malformed sentinel")?;
                cursor = pass_end;
            }
        }
    }

    stats.sessions_observed = state.keys.len();
    Ok(stats)
}

struct SessionState {
    keys: HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
    /// Per-session next-expected sequence number. We only populate
    /// this once we have authenticated at least one record from the
    /// session, so we never treat attacker-controlled `seq` from a
    /// failed-auth record as ground truth.
    expected_seq: HashMap<[u8; SESSION_ID_LEN], u64>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            expected_seq: HashMap::new(),
        }
    }

    fn aes_key(
        &mut self,
        gks: &ParsedGks,
        session_id: &[u8; SESSION_ID_LEN],
    ) -> anyhow::Result<&[u8; AES_KEY_LEN]> {
        if !self.keys.contains_key(session_id) {
            let key = crypto::derive_aes_key(gks, session_id)
                .context("deriving per-session AES key from GKS")?;
            self.keys.insert(*session_id, key);
        }
        Ok(self.keys.get(session_id).expect("just inserted above"))
    }
}

fn try_decrypt(
    gks: &ParsedGks,
    record: &Record,
    state: &mut SessionState,
) -> anyhow::Result<Vec<u8>> {
    let key = *state.aes_key(gks, &record.session_id)?;
    let plaintext = crypto::decrypt(
        &key,
        &record.session_id,
        record.seq,
        &record.nonce,
        &record.ciphertext,
        &record.tag,
    )
    .context("AES-256-GCM decrypt failed (tag mismatch or key/AAD wrong)")?;

    // Authenticated record. Now we can trust `record.seq` enough to
    // surface gaps to the user.
    if let Some(expected) = state.expected_seq.get(&record.session_id).copied() {
        if record.seq != expected {
            tracing::warn!(
                session_id = ?record.session_id,
                expected,
                got = record.seq,
                "encrypted-serial record sequence gap within session",
            );
        }
    }
    state
        .expected_seq
        .insert(record.session_id, record.seq.wrapping_add(1));

    Ok(plaintext)
}

fn handle_failure(
    strict: bool,
    output: &mut impl Write,
    offset: usize,
    reason: &str,
) -> anyhow::Result<()> {
    if strict {
        bail!("encrypted-serial record at offset {offset} failed: {reason}");
    }
    tracing::warn!(
        offset,
        reason,
        "encrypted-serial record could not be decoded"
    );
    write!(output, "<<decrypt failed offset={offset} reason={reason}>>")
        .context("writing decrypt-failed marker to output")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhcl_serial_console_crypto::consts::NONCE_LEN;
    use openhcl_serial_console_crypto::crypto::derive_aes_key;
    use openhcl_serial_console_crypto::crypto::encrypt;
    use openhcl_serial_console_crypto::format::Record;
    use openhcl_serial_console_crypto::gks::parse_gks;

    /// A real, deterministic TPM Import payload (lifted from
    /// `vm/devices/tpm/tpm_lib/src/lib.rs:3023-3054`).
    const SAMPLE_IMPORT_BLOB: &[u8] = &[
        0x01, 0x16, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xec, 0x0d, 0xdf, 0xf3,
        0xa2, 0x0f, 0xd4, 0x66, 0xe8, 0x53, 0x8a, 0x1c, 0x54, 0x00, 0x69, 0xbe, 0x57, 0xc4,
        0x9a, 0x7d, 0x4d, 0xd2, 0xbc, 0xd7, 0x6b, 0x93, 0xe4, 0x15, 0x3f, 0x2f, 0xbb, 0x77,
        0xf7, 0x1b, 0x19, 0x88, 0x04, 0xc7, 0x42, 0xda, 0xa2, 0x00, 0xc7, 0x8c, 0x2a, 0xfc,
        0x48, 0xa5, 0xe7, 0x3f, 0x4e, 0x06, 0x33, 0xa8, 0xb1, 0xcf, 0x09, 0x8c, 0xfe, 0x3f,
        0x91, 0x43, 0xa9, 0x4a, 0x8e, 0x05, 0xe7, 0xf0, 0x57, 0x68, 0xb5, 0x68, 0xe7, 0x7d,
        0xb3, 0x5c, 0xd5, 0x6c, 0xb9, 0x48, 0x5e, 0x0f, 0xf9, 0x0f, 0xe9, 0xf9, 0x42, 0x57,
        0x08, 0x8c, 0xff, 0x3f, 0x67, 0xd1, 0x9b, 0xb6, 0xa7, 0x7d, 0xa6, 0xa9, 0xcb, 0x00,
        0x4b, 0x1d, 0xa6, 0xf3, 0x09, 0xe0, 0x87, 0x12, 0xc6, 0x8b, 0xbe, 0x61, 0xaf, 0xc6,
        0x30, 0x35, 0xcc, 0x10, 0x68, 0x8b, 0x76, 0x36, 0x16, 0xcb, 0xce, 0x83, 0x6c, 0x7e,
        0x9e, 0x1e, 0x08, 0xc7, 0x20, 0x7d, 0x1d, 0xd4, 0xc4, 0x4f, 0x3a, 0x34, 0x06, 0xe9,
        0xae, 0xf5, 0x50, 0xd9, 0x5d, 0xb2, 0x30, 0x74, 0xed, 0x38, 0x74, 0x31, 0x3e, 0x1d,
        0xfd, 0x15, 0x26, 0x8f, 0x48, 0x5b, 0x22, 0x2f, 0xa0, 0xc3, 0xd0, 0x1c, 0x56, 0x4f,
        0xb1, 0x39, 0xe7, 0x93, 0xc1, 0x3d, 0x2d, 0x42, 0x57, 0x33, 0x4d, 0xdc, 0x90, 0x41,
        0x83, 0x6a, 0x21, 0x15, 0xbd, 0x2c, 0x5c, 0xa1, 0xc1, 0xda, 0xf9, 0x4c, 0x15, 0x89,
        0x41, 0x84, 0xad, 0xb9, 0xfc, 0xc7, 0x81, 0xa3, 0x93, 0xe9, 0xd8, 0xfc, 0xe3, 0x3f,
        0x4d, 0x6f, 0x71, 0x14, 0x9e, 0xe2, 0xe2, 0xfa, 0xa1, 0x8d, 0x3a, 0x80, 0xea, 0x5a,
        0xc9, 0x0f, 0x23, 0xb9, 0x3e, 0x36, 0xbb, 0xff, 0x4e, 0x9c, 0x40, 0x6f, 0x1d, 0x75,
        0x39, 0x96, 0x9b, 0xac, 0x54, 0xe1, 0x0b, 0x4b, 0x08, 0x3e, 0xd5, 0x94, 0x7d, 0xad,
        0x00, 0x8a, 0x00, 0x88, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xf7, 0xca,
        0x88, 0xe3, 0x6a, 0x67, 0xbd, 0xb7, 0xfe, 0xc9, 0x49, 0x35, 0x84, 0x23, 0xf3, 0x26,
        0x7f, 0xaa, 0xf6, 0xee, 0x14, 0x86, 0x55, 0xbf, 0x26, 0xd3, 0x21, 0x9f, 0x8a, 0xb2,
        0x1f, 0x2e, 0x79, 0x69, 0x7b, 0xa0, 0xad, 0x06, 0x2e, 0x13, 0xda, 0x8a, 0x5c, 0x59,
        0x98, 0x75, 0xf5, 0xfa, 0x2e, 0x14, 0xe6, 0xef, 0xc2, 0x3c, 0xa6, 0x11, 0x90, 0xf8,
        0xc3, 0x6f, 0x7d, 0xc5, 0x4c, 0x5c, 0xe8, 0x6a, 0x7f, 0x24, 0xa0, 0xef, 0x70, 0x5e,
        0xc8, 0x92, 0xa2, 0x3c, 0xa8, 0xa4, 0x0b, 0x38, 0xb1, 0xd5, 0xeb, 0x67, 0x8f, 0x76,
        0x65, 0x73, 0xd5, 0x6b, 0xb1, 0xad, 0x85, 0xb0, 0x0b, 0x0e, 0x41, 0x6b, 0xba, 0x1c,
        0x2a, 0x02, 0x11, 0xb7, 0xb4, 0x72, 0x74, 0xe2, 0x9f, 0x8e, 0x42, 0xa1, 0x38, 0x24,
        0x25, 0xc8, 0xcf, 0x53, 0x27, 0x1b, 0x4e, 0xcc, 0x8c, 0x0b, 0x4b, 0x69, 0x3f, 0x7b,
        0x00, 0x00,
    ];

    fn sample_gks() -> ParsedGks {
        parse_gks(SAMPLE_IMPORT_BLOB).expect("sample import blob must parse")
    }

    fn make_record(
        gks: &ParsedGks,
        session_id: [u8; SESSION_ID_LEN],
        seq: u64,
        nonce: [u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Record {
        let key = derive_aes_key(gks, &session_id).unwrap();
        let (ciphertext, tag) = encrypt(&key, &session_id, seq, &nonce, plaintext).unwrap();
        Record {
            session_id,
            seq,
            nonce,
            ciphertext,
            tag,
        }
    }

    #[test]
    fn round_trip_single_record_no_passthrough() {
        let gks = sample_gks();
        let r = make_record(&gks, [0xa1; SESSION_ID_LEN], 0, [0xb1; NONCE_LEN], b"hello");
        let input = r.encode_to_string();
        let mut out = Vec::new();
        let stats = run(input.as_bytes(), &mut out, &gks, false).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(stats.records_ok, 1);
        assert_eq!(stats.records_failed, 0);
        assert_eq!(stats.sessions_observed, 1);
    }

    #[test]
    fn passthrough_around_records() {
        let gks = sample_gks();
        let session = [0xa2; SESSION_ID_LEN];
        let r1 = make_record(&gks, session, 0, [0x10; NONCE_LEN], b"ONE");
        let r2 = make_record(&gks, session, 1, [0x11; NONCE_LEN], b"TWO");

        let mut input = b"prefix\n".to_vec();
        input.extend_from_slice(r1.encode_to_string().as_bytes());
        input.extend_from_slice(b"\nmiddle\n");
        input.extend_from_slice(r2.encode_to_string().as_bytes());
        input.extend_from_slice(b"\ntrailing");

        let mut out = Vec::new();
        let stats = run(&input, &mut out, &gks, false).unwrap();
        assert_eq!(out, b"prefix\nONE\nmiddle\nTWO\ntrailing");
        assert_eq!(stats.records_ok, 2);
    }

    #[test]
    fn multi_session_capture() {
        let gks = sample_gks();
        let s1 = [0xc1; SESSION_ID_LEN];
        let s2 = [0xc2; SESSION_ID_LEN];
        let r1 = make_record(&gks, s1, 0, [0x10; NONCE_LEN], b"A");
        let r2 = make_record(&gks, s2, 0, [0x10; NONCE_LEN], b"B");
        let r3 = make_record(&gks, s1, 1, [0x11; NONCE_LEN], b"C");

        let input = format!(
            "{}\n{}\n{}\n",
            r1.encode_to_string(),
            r2.encode_to_string(),
            r3.encode_to_string(),
        );
        let mut out = Vec::new();
        let stats = run(input.as_bytes(), &mut out, &gks, false).unwrap();
        assert_eq!(out, b"A\nB\nC\n");
        assert_eq!(stats.records_ok, 3);
        assert_eq!(stats.sessions_observed, 2);
    }

    #[test]
    fn tampered_tag_default_emits_marker() {
        let gks = sample_gks();
        let mut r = make_record(&gks, [0xd1; SESSION_ID_LEN], 0, [0xee; NONCE_LEN], b"x");
        r.tag[0] ^= 1;
        let input = r.encode_to_string();
        let mut out = Vec::new();
        let stats = run(input.as_bytes(), &mut out, &gks, false).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<<decrypt failed offset="), "got: {s:?}");
        assert_eq!(stats.records_ok, 0);
        assert_eq!(stats.records_failed, 1);
    }

    #[test]
    fn tampered_tag_strict_errors() {
        let gks = sample_gks();
        let mut r = make_record(&gks, [0xd2; SESSION_ID_LEN], 0, [0xee; NONCE_LEN], b"x");
        r.tag[0] ^= 1;
        let input = r.encode_to_string();
        let mut out = Vec::new();
        let err = run(input.as_bytes(), &mut out, &gks, true).unwrap_err();
        assert!(err.to_string().contains("offset"), "got: {err:#}");
    }

    #[test]
    fn malformed_sentinel_default_passes_through() {
        // Plaintext containing the literal opening sentinel but not
        // a valid base64 body. Default mode must NOT eat it; strict
        // mode rejects.
        let gks = sample_gks();
        let input = b"hello [[OHENC v1 not_valid_base64_content_here]] world";
        let mut out = Vec::new();
        let stats = run(input, &mut out, &gks, false).unwrap();
        // We pass through `[`, then the rest of the sentinel-looking
        // text gets re-scanned for sentinels and ultimately ends up
        // in the output unchanged. The exact byte-for-byte output
        // from an aggressive scanner is implementation-defined; what
        // matters is that we don't lose plaintext silently.
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("hello "), "got: {s:?}");
        assert!(s.contains("world"), "got: {s:?}");
        assert_eq!(stats.records_ok, 0);
    }

    #[test]
    fn malformed_sentinel_strict_errors() {
        let gks = sample_gks();
        let input = b"[[OHENC v1 not_valid_base64_content]]";
        let mut out = Vec::new();
        let err = run(input, &mut out, &gks, true).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err:#}");
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let gks = sample_gks();
        let mut out = Vec::new();
        let stats = run(b"", &mut out, &gks, false).unwrap();
        assert!(out.is_empty());
        assert_eq!(stats.records_ok, 0);
    }
}
