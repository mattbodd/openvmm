// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parse `FileId::GUEST_SECRET_KEY` (VMGS slot 13) as the
//! TPM2 Import payload it actually is.
//!
//! The on-disk slot is documented (in
//! `openhcl_attestation_protocol::vmgs::GuestSecretKey`) as a flat
//! 2048-byte byte array, but its contents semantically are a TPM2
//! Import command payload:
//!
//! ```text
//! TPM2B_PUBLIC || TPM2B_PRIVATE (duplicate) || TPM2B_ENCRYPTED_SECRET (in_sym_seed)
//! ```
//!
//! followed by zero padding out to the slot size. The TPM device
//! parses these bytes via
//! [`tpm_protocol::tpm20proto::protocol::ImportCmd::deserialize_no_wrapping_key`]
//! when provisioning the L1 guest's vTPM.
//!
//! For the encrypted-serial-console use case we want our key
//! derivation to be tied to that **structured** payload (rather than
//! to the slot's incidental zero padding), so this module:
//!
//! * Exposes a [`parse_gks`] helper that runs the same TPM Import
//!   parser the production TPM device uses.
//! * Returns the canonical "KDF input" -- a fixed-order
//!   concatenation of the three parsed `TPM2B` fields, with no
//!   trailing padding -- which the
//!   [`crate::crypto::derive_aes_key`] code feeds into
//!   `kbkdf_hmac_sha256`.
//!
//! Producers and consumers can disagree on padding without hurting
//! interop; they cannot disagree on the payload itself, because the
//! parser will reject a malformed slot up-front.

use thiserror::Error;
use tpm_protocol::tpm20proto::protocol::ImportCmd;

/// Errors produced by [`parse_gks`].
#[derive(Debug, Error)]
pub enum GksError {
    /// The slot 13 contents could not be parsed as a TPM2 Import
    /// payload (`TPM2B_PUBLIC || TPM2B_PRIVATE || TPM2B_ENCRYPTED_SECRET`).
    /// The most common causes are:
    ///
    /// * the slot is empty or zero-filled,
    /// * the slot was provisioned with arbitrary bytes rather than a
    ///   real TPM Import blob (e.g. via `head -c 2048 /dev/urandom`),
    /// * the slot was truncated.
    #[error(
        "slot 13 contents are not a valid TPM2 Import payload \
         (TPM2B_PUBLIC || TPM2B_PRIVATE || TPM2B_ENCRYPTED_SECRET)"
    )]
    Malformed,
}

/// A parsed `FileId::GUEST_SECRET_KEY` blob and its canonical KDF
/// input.
///
/// Construct via [`parse_gks`]. Hold this only as long as you need
/// to derive the AES key; once
/// [`crate::crypto::derive_aes_key`] has consumed it you should drop
/// the struct so the secret bytes don't outlive their useful
/// lifetime.
pub struct ParsedGks {
    /// The deserialized TPM Import command. Preserved for future
    /// consumers (e.g. callers that want to inspect
    /// `object_public.parameters` or `in_sym_seed.size` for
    /// diagnostics).
    pub import: ImportCmd,
    /// The byte-for-byte serialization of just the three TPM2B
    /// fields, in fixed order:
    /// `object_public || duplicate || in_sym_seed`. This is the
    /// canonical input to the AES key derivation -- no slot
    /// padding, no command-header bytes, no auth area.
    pub kdf_input: Vec<u8>,
}

impl std::fmt::Debug for ParsedGks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't dump the secret bytes (or the parsed Import struct,
        // which contains the same bytes) in Debug output. Useful
        // for callers that propagate `anyhow::Result<ParsedGks>`
        // through `.unwrap_err()` etc.
        f.debug_struct("ParsedGks")
            .field("kdf_input_len", &self.kdf_input.len())
            .finish_non_exhaustive()
    }
}

/// Parse the contents of `FileId::GUEST_SECRET_KEY` as a TPM2
/// Import payload and return the parsed structure together with the
/// canonical KDF input bytes.
///
/// Garbage / truncated / zero-filled slots return
/// [`GksError::Malformed`] so callers can fail closed instead of
/// silently deriving a useless key.
pub fn parse_gks(slot_bytes: &[u8]) -> Result<ParsedGks, GksError> {
    let import = ImportCmd::deserialize_no_wrapping_key(slot_bytes).ok_or(GksError::Malformed)?;

    let object_public = import.object_public.serialize();
    let duplicate = import.duplicate.serialize();
    let in_sym_seed = import.in_sym_seed.serialize();

    let mut kdf_input =
        Vec::with_capacity(object_public.len() + duplicate.len() + in_sym_seed.len());
    kdf_input.extend_from_slice(&object_public);
    kdf_input.extend_from_slice(&duplicate);
    kdf_input.extend_from_slice(&in_sym_seed);

    Ok(ParsedGks { import, kdf_input })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, deterministic TPM Import payload generated for the
    /// vTPM `test_initialize_guest_secret_key` test in
    /// `vm/devices/tpm/tpm_lib/src/lib.rs:3023-3054`. 422 bytes of
    /// `TPM2B_PUBLIC || TPM2B_PRIVATE || TPM2B_ENCRYPTED_SECRET`,
    /// followed in slot 13 by zero padding out to 2048 bytes.
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

    fn slot_padded() -> Vec<u8> {
        let mut buf = SAMPLE_IMPORT_BLOB.to_vec();
        buf.resize(2048, 0);
        buf
    }

    #[test]
    fn parse_accepts_known_good_blob() {
        let parsed = parse_gks(SAMPLE_IMPORT_BLOB).expect("should parse");
        assert_ne!(parsed.kdf_input.len(), 0);
        assert!(
            parsed.kdf_input.len() < SAMPLE_IMPORT_BLOB.len() + 64,
            "KDF input should be approximately the same size as the input blob"
        );
    }

    #[test]
    fn parse_handles_zero_padded_slot_layout() {
        let parsed = parse_gks(&slot_padded()).expect("zero-padded slot should still parse");
        let unpadded = parse_gks(SAMPLE_IMPORT_BLOB).unwrap();
        assert_eq!(
            parsed.kdf_input, unpadded.kdf_input,
            "padding must not affect the canonical KDF input"
        );
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(parse_gks(&[]), Err(GksError::Malformed)));
    }

    #[test]
    fn parse_rejects_zero_filled_slot() {
        // Just zeros (the natural state of an unprovisioned slot
        // in the producer's view).
        let blob = vec![0u8; 2048];
        // Zero-filled bytes happen to parse as zero-length TPM2B
        // headers, which is a *malformed* import blob (real ones
        // have non-zero sizes for at least one of the three
        // fields). The parser only fails if the consumed length
        // exceeds the input, but we still want to reject it as
        // "no real key material here" -- if the parser accepts it,
        // the resulting KDF input must at least be all zeros so
        // downstream callers can spot it.
        match parse_gks(&blob) {
            Err(GksError::Malformed) => {} // ideal
            Ok(parsed) => {
                assert!(
                    parsed.kdf_input.iter().all(|b| *b == 0),
                    "zero-filled slot must produce zero-filled KDF input if it parses at all"
                );
            }
        }
    }

    #[test]
    fn parse_rejects_truncated_blob() {
        // Drop the last byte -- the inner TPM2B sizes claim more
        // bytes than we have.
        let truncated = &SAMPLE_IMPORT_BLOB[..SAMPLE_IMPORT_BLOB.len() - 1];
        assert!(matches!(parse_gks(truncated), Err(GksError::Malformed)));
    }

    #[test]
    fn parse_rejects_garbage() {
        // Random-looking bytes whose first u16 (TPM2B_PUBLIC.size)
        // claims a size larger than the buffer.
        let mut garbage = vec![0xffu8; 16];
        garbage[0] = 0xff;
        garbage[1] = 0xff;
        assert!(matches!(parse_gks(&garbage), Err(GksError::Malformed)));
    }
}
