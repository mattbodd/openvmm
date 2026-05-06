// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key derivation and AES-256-GCM encrypt/decrypt for the encrypted
//! serial console wire format.

use crate::consts::AES_KEY_LEN;
use crate::consts::KDF_LABEL;
use crate::consts::NONCE_LEN;
use crate::consts::SESSION_ID_LEN;
use crate::consts::TAG_LEN;
use crate::format::build_aad;
use crate::gks::ParsedGks;
use thiserror::Error;

/// Length in bytes of the GKS blob carried in
/// `FileId::GUEST_SECRET_KEY`. Mirrors the value in
/// `openhcl_attestation_protocol::vmgs::GUEST_SECRET_KEY_MAX_SIZE`;
/// duplicated here so this crate does not need to depend on the
/// attestation-protocol crate.
pub const GKS_LEN: usize = 2048;

const _: () = assert!(GKS_LEN > 0);

/// Derive the per-session AES-256-GCM key from a parsed
/// `FileId::GUEST_SECRET_KEY` blob and the session identifier
/// carried in the record.
///
/// The KDF input is the canonical structured payload from
/// [`crate::gks::parse_gks`] (i.e. `object_public || duplicate ||
/// in_sym_seed`, no slot padding) -- not the raw 2048-byte slot
/// view. This means producer and decryptor agree on the derived key
/// regardless of how either side chose to pad slot 13.
///
/// The decryptor caches the resulting key per `session_id` so it
/// does not re-run the KDF for every record.
pub fn derive_aes_key(
    gks: &ParsedGks,
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<[u8; AES_KEY_LEN], CryptoError> {
    let derived =
        crypto::kdf::kbkdf_hmac_sha256(&gks.kdf_input, KDF_LABEL, session_id, AES_KEY_LEN)
            .map_err(CryptoError::Kdf)?;
    let arr: [u8; AES_KEY_LEN] = derived
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DerivedKeyLength { got: derived.len() })?;
    Ok(arr)
}

/// Encrypt `plaintext` for inclusion in a record. The returned tuple
/// is `(ciphertext, tag)`; both go into the wire-format payload as-is
/// alongside `session_id`, `seq`, and `nonce`.
///
/// `session_id` and `seq` are bound to the AEAD via AAD so the
/// decryptor will reject any record where either has been tampered
/// with.
pub fn encrypt(
    aes_key: &[u8; AES_KEY_LEN],
    session_id: &[u8; SESSION_ID_LEN],
    seq: u64,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), CryptoError> {
    let aad = build_aad(session_id, seq);
    let aes = crypto::aes_256_gcm::Aes256Gcm::new(aes_key).map_err(CryptoError::Aes)?;
    let mut enc_ctx = aes.encrypt().map_err(CryptoError::Aes)?;
    let mut tag = [0u8; TAG_LEN];
    let ciphertext = enc_ctx
        .cipher_with_aad(nonce, &aad, plaintext, &mut tag)
        .map_err(CryptoError::Aes)?;
    Ok((ciphertext, tag))
}

/// Decrypt and authenticate the ciphertext from a single record.
///
/// `session_id` and `seq` MUST be the values pulled from the wire
/// format payload; they are rebuilt into AAD and verified against the
/// `tag`. Any mutation to the wire-format header bits AAD covers (the
/// version domain string, `session_id`, `seq`) makes this fail.
pub fn decrypt(
    aes_key: &[u8; AES_KEY_LEN],
    session_id: &[u8; SESSION_ID_LEN],
    seq: u64,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let aad = build_aad(session_id, seq);
    let aes = crypto::aes_256_gcm::Aes256Gcm::new(aes_key).map_err(CryptoError::Aes)?;
    let mut dec_ctx = aes.decrypt().map_err(CryptoError::Aes)?;
    dec_ctx
        .cipher_with_aad(nonce, &aad, ciphertext, tag)
        .map_err(CryptoError::Aes)
}

/// Errors produced by the encrypt/decrypt helpers.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The KDF backend failed.
    #[error("failed to derive AES key from GKS")]
    Kdf(#[source] crypto::kdf::KdfError),
    /// The AES-256-GCM backend failed (e.g. tag verification).
    #[error("AES-256-GCM operation failed")]
    Aes(#[source] crypto::aes_256_gcm::Aes256GcmError),
    /// The KDF returned an unexpected number of bytes.
    #[error("KDF produced {got} bytes, expected {AES_KEY_LEN}")]
    DerivedKeyLength {
        /// The unexpected length returned by the KDF.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gks::parse_gks;

    /// A real, deterministic TPM Import payload (the same fixture
    /// `gks::tests` uses, lifted from
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

    #[test]
    fn round_trip() {
        let gks = sample_gks();
        let session_id = [0xaau8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x11u8; NONCE_LEN];
        let plain = b"hello, encrypted serial console";

        let (cipher, tag) = encrypt(&key, &session_id, 7, &nonce, plain).unwrap();
        let recovered = decrypt(&key, &session_id, 7, &nonce, &cipher, &tag).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let gks = sample_gks();
        let session_id = [0x55u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x22u8; NONCE_LEN];

        let (cipher, tag) = encrypt(&key, &session_id, 0, &nonce, b"").unwrap();
        assert!(cipher.is_empty());
        let recovered = decrypt(&key, &session_id, 0, &nonce, &cipher, &tag).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn aad_binding_session_id() {
        let gks = sample_gks();
        let session_id = [0x55u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x33u8; NONCE_LEN];
        let plain = b"x";

        let (cipher, tag) = encrypt(&key, &session_id, 1, &nonce, plain).unwrap();
        let mut tampered = session_id;
        tampered[0] ^= 1;
        let res = decrypt(&key, &tampered, 1, &nonce, &cipher, &tag);
        assert!(res.is_err(), "wrong session_id in AAD must fail");
    }

    #[test]
    fn aad_binding_seq() {
        let gks = sample_gks();
        let session_id = [0x66u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x44u8; NONCE_LEN];
        let plain = b"x";

        let (cipher, tag) = encrypt(&key, &session_id, 1, &nonce, plain).unwrap();
        let res = decrypt(&key, &session_id, 2, &nonce, &cipher, &tag);
        assert!(res.is_err(), "wrong seq in AAD must fail");
    }

    #[test]
    fn nonce_tampering() {
        let gks = sample_gks();
        let session_id = [0x77u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x55u8; NONCE_LEN];
        let plain = b"abc";

        let (cipher, tag) = encrypt(&key, &session_id, 9, &nonce, plain).unwrap();
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 1;
        let res = decrypt(&key, &session_id, 9, &bad_nonce, &cipher, &tag);
        assert!(res.is_err(), "wrong nonce must fail");
    }

    #[test]
    fn ciphertext_tampering() {
        let gks = sample_gks();
        let session_id = [0x88u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x66u8; NONCE_LEN];
        let plain = b"abc";

        let (cipher, tag) = encrypt(&key, &session_id, 9, &nonce, plain).unwrap();
        let mut bad = cipher.clone();
        bad[0] ^= 1;
        let res = decrypt(&key, &session_id, 9, &nonce, &bad, &tag);
        assert!(res.is_err(), "tampered ciphertext must fail");
    }

    #[test]
    fn tag_tampering() {
        let gks = sample_gks();
        let session_id = [0x99u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x77u8; NONCE_LEN];
        let plain = b"abc";

        let (cipher, mut tag) = encrypt(&key, &session_id, 9, &nonce, plain).unwrap();
        tag[0] ^= 1;
        let res = decrypt(&key, &session_id, 9, &nonce, &cipher, &tag);
        assert!(res.is_err(), "tampered tag must fail");
    }

    #[test]
    fn per_session_key_isolation() {
        let gks = sample_gks();
        let session_a = [0x01u8; SESSION_ID_LEN];
        let session_b = [0x02u8; SESSION_ID_LEN];
        let key_a = derive_aes_key(&gks, &session_a).unwrap();
        let key_b = derive_aes_key(&gks, &session_b).unwrap();
        assert_ne!(
            key_a, key_b,
            "different sessions must derive different keys"
        );

        let nonce = [0x88u8; NONCE_LEN];
        let plain = b"x";
        let (cipher, tag) = encrypt(&key_a, &session_a, 0, &nonce, plain).unwrap();

        // Decrypting with session B's key should fail (different
        // key); decrypting with session A's key but session_b in AAD
        // should also fail.
        let res = decrypt(&key_b, &session_a, 0, &nonce, &cipher, &tag);
        assert!(res.is_err());
        let res = decrypt(&key_a, &session_b, 0, &nonce, &cipher, &tag);
        assert!(res.is_err());
    }

    #[test]
    fn slot_padding_does_not_affect_derived_key() {
        // The whole point of going through parse_gks: a slot 13
        // entry that has trailing zeros and one that doesn't must
        // produce identical AES keys.
        let unpadded = parse_gks(SAMPLE_IMPORT_BLOB).unwrap();
        let mut padded_bytes = SAMPLE_IMPORT_BLOB.to_vec();
        padded_bytes.resize(GKS_LEN, 0);
        let padded = parse_gks(&padded_bytes).unwrap();

        let session_id = [0xc0u8; SESSION_ID_LEN];
        let k_unpadded = derive_aes_key(&unpadded, &session_id).unwrap();
        let k_padded = derive_aes_key(&padded, &session_id).unwrap();
        assert_eq!(k_unpadded, k_padded);
    }

    #[test]
    fn kdf_known_answer() {
        // Pin the (parsed GKS + session_id) -> AES key derivation
        // against the canonical SAMPLE_IMPORT_BLOB. If a future
        // change to the KDF label, output length, salt usage, or
        // canonical KDF input layout breaks this test, that is by
        // design -- the producer side must derive the same key
        // bit-for-bit.
        let gks = sample_gks();
        let session_id = [0u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        // Re-pin once we run the test for real (the previous KAT
        // was over the unparsed [0..255] cycle, which is a
        // different KDF input now). The actual hex string is
        // filled in by running this test once and copying the
        // produced value.
        let actual = hex::encode(key);
        assert_eq!(
            actual, KAT_EXPECTED_KEY,
            "if this is the first run after switching to the structured KDF input, \
             paste the actual value into KAT_EXPECTED_KEY below this line."
        );
    }

    /// Pinned output of the `kdf_known_answer` derivation. Computed
    /// once with the structured KDF input from
    /// [`SAMPLE_IMPORT_BLOB`] + an all-zero session_id; any future
    /// change to the canonical KDF input or the KDF parameters
    /// will fail the KAT and require re-pinning.
    const KAT_EXPECTED_KEY: &str =
        "076b92068799d801c0740e6fcf03303bc469f2596c1aa9b889b27b7f8549ec9c";
}
