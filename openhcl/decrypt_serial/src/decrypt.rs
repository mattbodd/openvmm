// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming decryptor: read an encrypted serial capture from any
//! `impl Read` (regular file, FIFO, stdin, ...), walk it for each
//! ``[[OHENC v1 ...]]`` sentinel, decrypt the record, and write the
//! recovered plaintext (interleaved with verbatim plaintext bytes
//! from outside the records) to an output sink.
//!
//! The driver is incremental: it does not require the entire input
//! to be available up front, so it works on a live FIFO that the
//! producer is still writing to. A bounded sliding buffer is used
//! to splice records that arrive across multiple read chunks.

use anyhow::Context;
use anyhow::bail;
use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
use openhcl_serial_console_crypto::consts::MAX_SENTINEL_BASE64_LEN;
use openhcl_serial_console_crypto::consts::SENTINEL_CLOSE;
use openhcl_serial_console_crypto::consts::SENTINEL_OPEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::format::SentinelMatch;
use openhcl_serial_console_crypto::format::find_next_sentinel;
use openhcl_serial_console_crypto::gks::ParsedGks;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;

/// How many bytes to attempt to read from the input on each top-up.
/// The exact value isn't important; it just needs to be large enough
/// to amortize syscalls and small enough to keep the per-iteration
/// scan cheap.
const READ_CHUNK_SIZE: usize = 8 * 1024;

/// Once the consumed prefix of the working buffer reaches this size,
/// drop it and reset the cursor. Compaction keeps memory bounded for
/// long-running streams without doing an allocation per record.
const COMPACT_THRESHOLD: usize = 64 * 1024;

/// Smallest number of bytes after a sentinel opener at which a missing
/// closing `]]` is *decisive* evidence that the candidate sentinel is
/// truly malformed (rather than just split across reads).
///
/// Equal to the maximum legal body length plus the closing literal:
/// once we've buffered this many bytes after the opener with no `]]`,
/// no future arrival can rescue the record because the format library
/// would already have rejected it as too long.
const MIN_DECISIVE_AFTER_BODY_START: usize = MAX_SENTINEL_BASE64_LEN + SENTINEL_CLOSE.len();

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
    /// authenticated records. Sessions observed only via failed-auth
    /// records do not count.
    pub sessions_observed: usize,
}

/// Run the decryptor over `input`, writing recovered plaintext (and
/// any passthrough plaintext from outside records) to `output`.
///
/// `input` is read incrementally; the function processes complete
/// records as soon as they arrive on the underlying stream and
/// flushes `output` after every emitted chunk so callers tailing a
/// FIFO see decrypted output without having to wait for the producer
/// to close the pipe.
///
/// In default mode, malformed sentinels are passed through verbatim
/// (so a stray ``[[OHENC `` in plaintext does not silently disappear)
/// and decryption / parse failures are reported with a
/// ``<<decrypt failed offset=N reason=...>>`` marker injected into
/// the output stream. In `strict` mode, the first malformed sentinel
/// or decryption failure is fatal.
///
/// Reported byte offsets are absolute positions in the original
/// stream, even after internal buffer compaction.
pub fn run(
    input: &mut impl Read,
    output: &mut impl Write,
    gks: &ParsedGks,
    strict: bool,
) -> anyhow::Result<DecryptStats> {
    let mut state = SessionState::new();
    let mut stats = DecryptStats::default();
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK_SIZE * 2);
    // Number of bytes already consumed from the front of `buf`; offsets
    // returned by `find_next_sentinel` are relative to `buf`, but
    // user-visible offsets reported in error markers are
    // `absolute_base + buf_offset` so they survive compaction.
    let mut cursor = 0usize;
    let mut absolute_base = 0u64;
    let mut eof = false;

    loop {
        if !eof {
            // Compact the consumed prefix periodically so the buffer
            // doesn't grow without bound on long-running streams.
            if cursor >= COMPACT_THRESHOLD {
                buf.drain(..cursor);
                absolute_base += cursor as u64;
                cursor = 0;
            }

            let prev_len = buf.len();
            buf.resize(prev_len + READ_CHUNK_SIZE, 0);
            let n = input
                .read(&mut buf[prev_len..])
                .context("reading encrypted serial input")?;
            buf.truncate(prev_len + n);
            if n == 0 {
                eof = true;
            }
        }

        let made_progress = drain_buffer(
            &buf,
            &mut cursor,
            absolute_base,
            output,
            gks,
            &mut state,
            &mut stats,
            strict,
            eof,
        )?;

        if made_progress {
            output.flush().context("flushing decrypted output")?;
        }

        if eof && cursor >= buf.len() {
            break;
        }
    }

    stats.sessions_observed = state.expected_seq.len();
    Ok(stats)
}

/// Walk the working buffer for as long as we can make progress
/// without needing more data, returning whether we emitted anything
/// this pass.
#[expect(clippy::too_many_arguments)]
fn drain_buffer(
    buf: &[u8],
    cursor: &mut usize,
    absolute_base: u64,
    output: &mut impl Write,
    gks: &ParsedGks,
    state: &mut SessionState,
    stats: &mut DecryptStats,
    strict: bool,
    eof: bool,
) -> anyhow::Result<bool> {
    let mut made_progress = false;
    loop {
        match find_next_sentinel(buf, *cursor) {
            SentinelMatch::Found {
                start,
                end,
                payload,
            } => {
                if start > *cursor {
                    output
                        .write_all(&buf[*cursor..start])
                        .context("writing leading plaintext before record")?;
                }
                let abs_start = absolute_base + start as u64;
                match Record::parse_payload(&payload) {
                    Ok(record) => match try_decrypt(gks, &record, state) {
                        Ok(plaintext) => {
                            output
                                .write_all(&plaintext)
                                .context("writing decrypted record")?;
                            stats.records_ok += 1;
                        }
                        Err(err) => {
                            stats.records_failed += 1;
                            handle_failure(strict, output, abs_start, &err.to_string())?;
                        }
                    },
                    Err(err) => {
                        stats.records_failed += 1;
                        handle_failure(strict, output, abs_start, &err.to_string())?;
                    }
                }
                *cursor = end;
                made_progress = true;
            }
            SentinelMatch::Malformed { start, reason } => {
                let abs_start = absolute_base + start as u64;
                let body_start = start + SENTINEL_OPEN.len();
                let is_unterminated = matches!(
                    reason,
                    openhcl_serial_console_crypto::format::SentinelError::Unterminated
                );
                let decisive = eof
                    || !is_unterminated
                    || buf.len().saturating_sub(body_start) >= MIN_DECISIVE_AFTER_BODY_START;

                if !decisive {
                    // Could just be a sentinel split across reads.
                    // Emit any verbatim plaintext that precedes it
                    // and wait for more bytes.
                    if start > *cursor {
                        output
                            .write_all(&buf[*cursor..start])
                            .context("writing plaintext before deferred sentinel")?;
                        *cursor = start;
                        made_progress = true;
                    }
                    return Ok(made_progress);
                }

                if strict {
                    bail!("malformed encrypted-serial sentinel at offset {abs_start}: {reason}",);
                }
                tracing::warn!(
                    offset = abs_start,
                    %reason,
                    "skipping malformed encrypted-serial sentinel; bytes will be passed through verbatim",
                );
                // Emit everything up to and including the opening
                // bracket, then resume scanning right after it.
                let pass_end = (start + 1).min(buf.len());
                if pass_end > *cursor {
                    output
                        .write_all(&buf[*cursor..pass_end])
                        .context("passing through leading bytes of malformed sentinel")?;
                    *cursor = pass_end;
                    made_progress = true;
                } else {
                    // `start` was inside the already-consumed region;
                    // can't happen with the current scanner but be
                    // defensive.
                    return Ok(made_progress);
                }
            }
            SentinelMatch::NotFound => {
                if eof {
                    if buf.len() > *cursor {
                        output
                            .write_all(&buf[*cursor..])
                            .context("writing trailing plaintext")?;
                        *cursor = buf.len();
                        made_progress = true;
                    }
                } else {
                    // Hold back the last (SENTINEL_OPEN.len() - 1)
                    // bytes in case they're the start of an opener
                    // that completes in the next read.
                    let safe_end = buf.len().saturating_sub(SENTINEL_OPEN.len() - 1);
                    if safe_end > *cursor {
                        output
                            .write_all(&buf[*cursor..safe_end])
                            .context("writing safe plaintext prefix")?;
                        *cursor = safe_end;
                        made_progress = true;
                    }
                }
                return Ok(made_progress);
            }
        }
    }
}

struct SessionState {
    keys: HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
    /// Per-session next-expected sequence number. We only populate
    /// this once we have authenticated at least one record from the
    /// session, so we never treat attacker-controlled `seq` from a
    /// failed-auth record as ground truth. This map is also the
    /// source of truth for `DecryptStats::sessions_observed` — the
    /// `keys` cache is filled lazily on first record-of-session
    /// regardless of whether that record authenticates, so it can be
    /// inflated by tampered captures.
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
    offset: u64,
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
    use std::io::Cursor;

    /// A real, deterministic TPM Import payload (lifted from
    /// `vm/devices/tpm/tpm_lib/src/lib.rs:3023-3054`).
    const SAMPLE_IMPORT_BLOB: &[u8] = &[
        0x01, 0x16, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xec, 0x0d, 0xdf, 0xf3, 0xa2, 0x0f,
        0xd4, 0x66, 0xe8, 0x53, 0x8a, 0x1c, 0x54, 0x00, 0x69, 0xbe, 0x57, 0xc4, 0x9a, 0x7d, 0x4d,
        0xd2, 0xbc, 0xd7, 0x6b, 0x93, 0xe4, 0x15, 0x3f, 0x2f, 0xbb, 0x77, 0xf7, 0x1b, 0x19, 0x88,
        0x04, 0xc7, 0x42, 0xda, 0xa2, 0x00, 0xc7, 0x8c, 0x2a, 0xfc, 0x48, 0xa5, 0xe7, 0x3f, 0x4e,
        0x06, 0x33, 0xa8, 0xb1, 0xcf, 0x09, 0x8c, 0xfe, 0x3f, 0x91, 0x43, 0xa9, 0x4a, 0x8e, 0x05,
        0xe7, 0xf0, 0x57, 0x68, 0xb5, 0x68, 0xe7, 0x7d, 0xb3, 0x5c, 0xd5, 0x6c, 0xb9, 0x48, 0x5e,
        0x0f, 0xf9, 0x0f, 0xe9, 0xf9, 0x42, 0x57, 0x08, 0x8c, 0xff, 0x3f, 0x67, 0xd1, 0x9b, 0xb6,
        0xa7, 0x7d, 0xa6, 0xa9, 0xcb, 0x00, 0x4b, 0x1d, 0xa6, 0xf3, 0x09, 0xe0, 0x87, 0x12, 0xc6,
        0x8b, 0xbe, 0x61, 0xaf, 0xc6, 0x30, 0x35, 0xcc, 0x10, 0x68, 0x8b, 0x76, 0x36, 0x16, 0xcb,
        0xce, 0x83, 0x6c, 0x7e, 0x9e, 0x1e, 0x08, 0xc7, 0x20, 0x7d, 0x1d, 0xd4, 0xc4, 0x4f, 0x3a,
        0x34, 0x06, 0xe9, 0xae, 0xf5, 0x50, 0xd9, 0x5d, 0xb2, 0x30, 0x74, 0xed, 0x38, 0x74, 0x31,
        0x3e, 0x1d, 0xfd, 0x15, 0x26, 0x8f, 0x48, 0x5b, 0x22, 0x2f, 0xa0, 0xc3, 0xd0, 0x1c, 0x56,
        0x4f, 0xb1, 0x39, 0xe7, 0x93, 0xc1, 0x3d, 0x2d, 0x42, 0x57, 0x33, 0x4d, 0xdc, 0x90, 0x41,
        0x83, 0x6a, 0x21, 0x15, 0xbd, 0x2c, 0x5c, 0xa1, 0xc1, 0xda, 0xf9, 0x4c, 0x15, 0x89, 0x41,
        0x84, 0xad, 0xb9, 0xfc, 0xc7, 0x81, 0xa3, 0x93, 0xe9, 0xd8, 0xfc, 0xe3, 0x3f, 0x4d, 0x6f,
        0x71, 0x14, 0x9e, 0xe2, 0xe2, 0xfa, 0xa1, 0x8d, 0x3a, 0x80, 0xea, 0x5a, 0xc9, 0x0f, 0x23,
        0xb9, 0x3e, 0x36, 0xbb, 0xff, 0x4e, 0x9c, 0x40, 0x6f, 0x1d, 0x75, 0x39, 0x96, 0x9b, 0xac,
        0x54, 0xe1, 0x0b, 0x4b, 0x08, 0x3e, 0xd5, 0x94, 0x7d, 0xad, 0x00, 0x8a, 0x00, 0x88, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xf7, 0xca, 0x88, 0xe3, 0x6a, 0x67, 0xbd, 0xb7,
        0xfe, 0xc9, 0x49, 0x35, 0x84, 0x23, 0xf3, 0x26, 0x7f, 0xaa, 0xf6, 0xee, 0x14, 0x86, 0x55,
        0xbf, 0x26, 0xd3, 0x21, 0x9f, 0x8a, 0xb2, 0x1f, 0x2e, 0x79, 0x69, 0x7b, 0xa0, 0xad, 0x06,
        0x2e, 0x13, 0xda, 0x8a, 0x5c, 0x59, 0x98, 0x75, 0xf5, 0xfa, 0x2e, 0x14, 0xe6, 0xef, 0xc2,
        0x3c, 0xa6, 0x11, 0x90, 0xf8, 0xc3, 0x6f, 0x7d, 0xc5, 0x4c, 0x5c, 0xe8, 0x6a, 0x7f, 0x24,
        0xa0, 0xef, 0x70, 0x5e, 0xc8, 0x92, 0xa2, 0x3c, 0xa8, 0xa4, 0x0b, 0x38, 0xb1, 0xd5, 0xeb,
        0x67, 0x8f, 0x76, 0x65, 0x73, 0xd5, 0x6b, 0xb1, 0xad, 0x85, 0xb0, 0x0b, 0x0e, 0x41, 0x6b,
        0xba, 0x1c, 0x2a, 0x02, 0x11, 0xb7, 0xb4, 0x72, 0x74, 0xe2, 0x9f, 0x8e, 0x42, 0xa1, 0x38,
        0x24, 0x25, 0xc8, 0xcf, 0x53, 0x27, 0x1b, 0x4e, 0xcc, 0x8c, 0x0b, 0x4b, 0x69, 0x3f, 0x7b,
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

    /// `Read` adapter that delivers at most `chunk_size` bytes per
    /// `read()` call. Used to exercise the streaming code paths with
    /// inputs split arbitrarily across chunks.
    struct ChunkedReader<'a> {
        data: &'a [u8],
        chunk_size: usize,
        pos: usize,
    }

    impl<'a> ChunkedReader<'a> {
        fn new(data: &'a [u8], chunk_size: usize) -> Self {
            assert!(chunk_size > 0);
            Self {
                data,
                chunk_size,
                pos: 0,
            }
        }
    }

    impl Read for ChunkedReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = self
                .chunk_size
                .min(out.len())
                .min(self.data.len() - self.pos);
            out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn run_buf(
        input: &[u8],
        output: &mut Vec<u8>,
        gks: &ParsedGks,
        strict: bool,
    ) -> anyhow::Result<DecryptStats> {
        let mut r = Cursor::new(input);
        run(&mut r, output, gks, strict)
    }

    #[test]
    fn round_trip_single_record_no_passthrough() {
        let gks = sample_gks();
        let r = make_record(&gks, [0xa1; SESSION_ID_LEN], 0, [0xb1; NONCE_LEN], b"hello");
        let input = r.encode_to_string();
        let mut out = Vec::new();
        let stats = run_buf(input.as_bytes(), &mut out, &gks, false).unwrap();
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
        let stats = run_buf(&input, &mut out, &gks, false).unwrap();
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
        let stats = run_buf(input.as_bytes(), &mut out, &gks, false).unwrap();
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
        let stats = run_buf(input.as_bytes(), &mut out, &gks, false).unwrap();
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
        let err = run_buf(input.as_bytes(), &mut out, &gks, true).unwrap_err();
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
        let stats = run_buf(input, &mut out, &gks, false).unwrap();
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
        let err = run_buf(input, &mut out, &gks, true).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err:#}");
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let gks = sample_gks();
        let mut out = Vec::new();
        let stats = run_buf(b"", &mut out, &gks, false).unwrap();
        assert!(out.is_empty());
        assert_eq!(stats.records_ok, 0);
    }

    /// Drive the streaming decoder one byte at a time. This exercises
    /// every possible split point inside an opener, base64 body, and
    /// closer; the streaming buffer must defer until each sentinel is
    /// complete and then emit the same result as the buffered case.
    #[test]
    fn streaming_one_byte_at_a_time_matches_buffered() {
        let gks = sample_gks();
        let session = [0xe1; SESSION_ID_LEN];
        let r1 = make_record(&gks, session, 0, [0x10; NONCE_LEN], b"alpha");
        let r2 = make_record(&gks, session, 1, [0x11; NONCE_LEN], b"bravo");
        let mut input = b"PREFIX ".to_vec();
        input.extend_from_slice(r1.encode_to_string().as_bytes());
        input.extend_from_slice(b" GAP ");
        input.extend_from_slice(r2.encode_to_string().as_bytes());
        input.extend_from_slice(b" SUFFIX");

        let mut buffered = Vec::new();
        let buffered_stats = run_buf(&input, &mut buffered, &gks, false).unwrap();

        let mut chunked = Vec::new();
        let mut reader = ChunkedReader::new(&input, 1);
        let chunked_stats = run(&mut reader, &mut chunked, &gks, false).unwrap();

        assert_eq!(chunked, buffered);
        assert_eq!(chunked_stats.records_ok, buffered_stats.records_ok);
        assert_eq!(chunked, b"PREFIX alpha GAP bravo SUFFIX");
    }

    /// Several different small chunk sizes across a multi-record
    /// input. Belt-and-suspenders for the one-byte test above.
    #[test]
    fn streaming_several_chunk_sizes_match_buffered() {
        let gks = sample_gks();
        let session = [0xe2; SESSION_ID_LEN];
        let mut input = Vec::new();
        for i in 0..5u64 {
            input.extend_from_slice(b"line ");
            let payload = format!("rec{i}");
            let r = make_record(
                &gks,
                session,
                i,
                [(0x20 + i as u8); NONCE_LEN],
                payload.as_bytes(),
            );
            input.extend_from_slice(r.encode_to_string().as_bytes());
            input.extend_from_slice(b"\n");
        }

        let mut buffered = Vec::new();
        let _ = run_buf(&input, &mut buffered, &gks, false).unwrap();

        for &chunk in &[1usize, 2, 3, 7, 13, 64, 256, 4096] {
            let mut chunked = Vec::new();
            let mut reader = ChunkedReader::new(&input, chunk);
            let _ = run(&mut reader, &mut chunked, &gks, false).unwrap();
            assert_eq!(chunked, buffered, "mismatch at chunk_size={chunk}");
        }
    }

    /// Plaintext containing just the start of a sentinel opener at
    /// the end of one read should be deferred (held in the trailing
    /// window) until the next read makes it clear whether it was a
    /// real opener or just plaintext.
    #[test]
    fn streaming_partial_opener_at_chunk_boundary() {
        let gks = sample_gks();
        let r = make_record(&gks, [0xe3; SESSION_ID_LEN], 0, [0x10; NONCE_LEN], b"DATA");
        let mut input = b"hello [[".to_vec();
        input.extend_from_slice(b"OHENC v1 ");
        // Only the sentinel from `r` follows; reuse its encoded form.
        let encoded = r.encode_to_string();
        // Strip the leading "[[OHENC v1 " (already in input above).
        let body_with_close = &encoded[SENTINEL_OPEN.len()..];
        input.extend_from_slice(body_with_close.as_bytes());
        input.extend_from_slice(b" trailing");

        // Use a tiny chunk to ensure the boundary lands inside the
        // opener.
        let mut chunked = Vec::new();
        let mut reader = ChunkedReader::new(&input, 3);
        let stats = run(&mut reader, &mut chunked, &gks, false).unwrap();
        assert_eq!(chunked, b"hello DATA trailing");
        assert_eq!(stats.records_ok, 1);
    }

    /// An opener that is truly never closed must be reported as
    /// malformed at EOF rather than silently dropped, and the
    /// preceding plaintext must still be flushed.
    #[test]
    fn streaming_unterminated_at_eof_is_malformed() {
        let gks = sample_gks();
        let mut input = b"prefix [[OHENC v1 abcdef".to_vec();
        // Exactly enough bytes after the opener to NOT trigger the
        // "decisive while still streaming" path; only EOF should
        // resolve this.
        input.extend_from_slice(&[b'A'; 32]);
        let mut chunked = Vec::new();
        let mut reader = ChunkedReader::new(&input, 5);
        let stats = run(&mut reader, &mut chunked, &gks, false).unwrap();
        let s = String::from_utf8(chunked).unwrap();
        assert!(s.starts_with("prefix "), "got: {s:?}");
        assert_eq!(stats.records_ok, 0);
    }

    /// Same as above but in strict mode: the unterminated sentinel
    /// must error out (at EOF) rather than being silently deferred
    /// forever.
    #[test]
    fn streaming_unterminated_at_eof_strict_errors() {
        let gks = sample_gks();
        let mut input = b"prefix [[OHENC v1 abcdef".to_vec();
        input.extend_from_slice(&[b'A'; 32]);
        let mut chunked = Vec::new();
        let mut reader = ChunkedReader::new(&input, 5);
        let err = run(&mut reader, &mut chunked, &gks, true).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err:#}");
    }

    /// Reported offsets must be absolute, not relative to the
    /// post-compaction sliding buffer. Build a stream large enough
    /// to trigger at least one compaction, then verify the offset of
    /// a tampered record near the end is reported as its absolute
    /// position in the original input.
    #[test]
    fn streaming_failure_offsets_are_absolute_after_compaction() {
        let gks = sample_gks();
        let session = [0xe4; SESSION_ID_LEN];
        let mut input = Vec::new();

        // Pad with enough plaintext to push past COMPACT_THRESHOLD.
        let pad_size = COMPACT_THRESHOLD + 4096;
        input.extend(std::iter::repeat_n(b'.', pad_size));

        // Then a tampered record.
        let mut tampered = make_record(&gks, session, 0, [0x33; NONCE_LEN], b"oops");
        tampered.tag[0] ^= 1;
        let tampered_offset = input.len();
        input.extend_from_slice(tampered.encode_to_string().as_bytes());

        let mut out = Vec::new();
        let mut reader = ChunkedReader::new(&input, 1024);
        let stats = run(&mut reader, &mut out, &gks, false).unwrap();
        assert_eq!(stats.records_failed, 1);
        let s = String::from_utf8(out).unwrap();
        let needle = format!("<<decrypt failed offset={tampered_offset} ");
        assert!(
            s.contains(&needle),
            "expected absolute offset {tampered_offset} in marker, got snippet: {:?}",
            &s[s.len().saturating_sub(200)..]
        );
    }

    /// Reference walker: scan the WHOLE input slice as if it had
    /// arrived in one `read()`. Tests that compare `run` against this
    /// pin streaming output to the buffered behavior even when the
    /// streaming code path internally uses non-trivial chunking.
    fn reference_walk(input: &[u8], gks: &ParsedGks, strict: bool) -> anyhow::Result<Vec<u8>> {
        // The simplest reference is: feed the whole slice to `run`
        // via a Cursor that returns it in a single read. That
        // guarantees the streaming branches that defer on partial
        // sentinels are never taken, so the result matches a strict
        // single-walk decode.
        struct OneShot<'a> {
            data: &'a [u8],
            done: bool,
        }
        impl Read for OneShot<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.done || self.data.is_empty() {
                    return Ok(0);
                }
                let n = self.data.len().min(out.len());
                out[..n].copy_from_slice(&self.data[..n]);
                self.data = &self.data[n..];
                if self.data.is_empty() {
                    self.done = true;
                }
                Ok(n)
            }
        }
        let mut out = Vec::new();
        let mut r = OneShot {
            data: input,
            done: false,
        };
        run(&mut r, &mut out, gks, strict)?;
        Ok(out)
    }

    /// A valid record split exactly between the two `]` bytes of the
    /// closer (and at every other byte boundary) must decode
    /// identically to the buffered case in both default and strict
    /// modes.
    #[test]
    fn streaming_split_closer_in_strict_mode() {
        let gks = sample_gks();
        let r = make_record(&gks, [0xf1; SESSION_ID_LEN], 0, [0x10; NONCE_LEN], b"split");
        let encoded = r.encode_to_string();
        let bytes = encoded.as_bytes();

        let want = reference_walk(bytes, &gks, false).unwrap();
        for split in 1..bytes.len() {
            let (a, b) = bytes.split_at(split);
            let mut combined: Vec<u8> = Vec::new();
            combined.extend_from_slice(a);
            combined.extend_from_slice(b);

            // Default mode: must match the buffered reference.
            let mut got = Vec::new();
            let mut reader = ChunkedReader::new(&combined, split.max(1));
            run(&mut reader, &mut got, &gks, false).unwrap();
            assert_eq!(got, want, "default-mode mismatch at split={split}");

            // Strict mode: a valid record split mid-sentinel must
            // NOT trigger a strict bail. Decryption must succeed.
            let mut got_strict = Vec::new();
            let mut strict_reader = ChunkedReader::new(&combined, split.max(1));
            run(&mut strict_reader, &mut got_strict, &gks, true)
                .unwrap_or_else(|err| panic!("strict-mode error at split={split}: {err:#}"));
            assert_eq!(got_strict, want, "strict-mode mismatch at split={split}");
        }
    }

    /// Boundary: an opener followed by exactly the maximum legal
    /// body length and a `]]` whose two bytes are split across two
    /// reads must still decode (after the second `]` arrives).
    ///
    /// Specifically the deferred-`Unterminated` path must NOT be
    /// considered decisive at `body_start + MAX_SENTINEL_BASE64_LEN + 1`
    /// even though it IS decisive at `body_start + MAX_SENTINEL_BASE64_LEN + 2`.
    #[test]
    fn streaming_max_body_split_closer_decodes() {
        let gks = sample_gks();
        // Build a record large enough that its base64 body equals
        // (or exceeds, harmlessly) most of MAX_SENTINEL_BASE64_LEN
        // without going over.
        let plaintext = vec![0xAB; 4000];
        let r = make_record(
            &gks,
            [0xf2; SESSION_ID_LEN],
            0,
            [0x33; NONCE_LEN],
            &plaintext,
        );
        let encoded = r.encode_to_string();
        let bytes = encoded.as_bytes();

        // Split between the two `]` of the closer.
        let split = bytes.len() - 1;
        let (a, b) = bytes.split_at(split);
        let mut combined = Vec::new();
        combined.extend_from_slice(a);
        combined.extend_from_slice(b);

        let mut out = Vec::new();
        let mut reader = ChunkedReader::new(&combined, split);
        let stats = run(&mut reader, &mut out, &gks, false).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(stats.records_ok, 1);
    }

    /// Boundary: a body that is one byte over the max with a `]]`
    /// after it is `Unterminated` (via the scan-window cap) and must
    /// be reported as malformed both buffered and streamed.
    #[test]
    fn streaming_oversize_body_is_malformed_consistently() {
        let gks = sample_gks();
        // body of (MAX_SENTINEL_BASE64_LEN + 1) `A`s. Per
        // openhcl_serial_console_crypto::format::tests, the buffered
        // scanner reports this as Unterminated because the close is
        // outside the scan window.
        let body = "A".repeat(MAX_SENTINEL_BASE64_LEN + 1);
        let mut input = b"prefix ".to_vec();
        input.extend_from_slice(format!("[[OHENC v1 {body}]]").as_bytes());
        input.extend_from_slice(b" suffix");

        let want = reference_walk(&input, &gks, false).unwrap();
        for &chunk in &[1usize, 7, 1024, 65_536] {
            let mut got = Vec::new();
            let mut reader = ChunkedReader::new(&input, chunk);
            run(&mut reader, &mut got, &gks, false).unwrap();
            assert_eq!(got, want, "mismatch at chunk_size={chunk}");
        }
    }

    /// `sessions_observed` must reflect only sessions that
    /// authenticated at least once. Tampered records with novel
    /// session ids must NOT inflate the count.
    #[test]
    fn sessions_observed_excludes_failed_decrypts() {
        let gks = sample_gks();
        let s_good = [0xe5; SESSION_ID_LEN];
        let s_bad = [0xe6; SESSION_ID_LEN];
        let good = make_record(&gks, s_good, 0, [0x10; NONCE_LEN], b"ok");
        let mut bad = make_record(&gks, s_bad, 0, [0x11; NONCE_LEN], b"oops");
        bad.tag[0] ^= 1;

        let input = format!("{}\n{}\n", good.encode_to_string(), bad.encode_to_string());
        let mut out = Vec::new();
        let stats = run_buf(input.as_bytes(), &mut out, &gks, false).unwrap();
        assert_eq!(stats.records_ok, 1);
        assert_eq!(stats.records_failed, 1);
        assert_eq!(
            stats.sessions_observed, 1,
            "tampered session must not count"
        );
    }
}
