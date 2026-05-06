// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resolve a [`openhcl_serial_console_crypto::gks::ParsedGks`] from
//! one of two CLI-supplied sources: a pre-extracted GKS blob, or a
//! plaintext VMGS file from which we read `FileId::GUEST_SECRET_KEY`
//! ourselves.
//!
//! Both paths first read the raw slot bytes (allowing the same
//! shorter-than-2048 / zero-padding behavior the production
//! `underhill_attestation::vmgs::read_guest_secret_key` permits) and
//! then parse them as a TPM2 Import payload. A slot that doesn't
//! parse fails closed with a friendly error -- the host-side
//! decryptor can't recover plaintext from it anyway.

use anyhow::Context;
use anyhow::bail;
use disk_backend::Disk;
use disk_vhd1::Vhd1Disk;
use openhcl_attestation_protocol::vmgs::GUEST_SECRET_KEY_MAX_SIZE;
use openhcl_serial_console_crypto::crypto::GKS_LEN;
use openhcl_serial_console_crypto::gks::ParsedGks;
use openhcl_serial_console_crypto::gks::parse_gks;
use std::path::Path;
use std::path::PathBuf;
use vmgs::Vmgs;
use vmgs_format::FileId;

// Belt-and-suspenders: keep the local constant in
// openhcl_serial_console_crypto in lockstep with the canonical
// definition in openhcl_attestation_protocol.
const _: () = assert!(GKS_LEN == GUEST_SECRET_KEY_MAX_SIZE);

/// Where the GKS bytes for decryption come from.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// A file containing a raw, pre-extracted `GuestSecretKey` blob
    /// (the bytes of `FileId::GUEST_SECRET_KEY` from a VMGS file).
    /// Up to [`GKS_LEN`] bytes; shorter files are zero-padded.
    Key(PathBuf),
    /// A plaintext VMGS file; the resolver will read
    /// `FileId::GUEST_SECRET_KEY` from it.
    Vmgs(PathBuf),
}

/// Resolve the [`KeySource`] into a parsed GuestSecretKey ready to
/// feed into [`openhcl_serial_console_crypto::crypto::derive_aes_key`].
pub async fn resolve(source: &KeySource) -> anyhow::Result<ParsedGks> {
    let (raw, label) = match source {
        KeySource::Key(p) => (read_key_file(p)?, "--key file"),
        KeySource::Vmgs(p) => (
            read_gks_from_vmgs_file(p).await?,
            "VMGS GUEST_SECRET_KEY entry",
        ),
    };
    parse_gks(&raw).with_context(|| {
        format!(
            "{label} contents are not a valid TPM2 Import payload \
             (TPM2B_PUBLIC || TPM2B_PRIVATE || TPM2B_ENCRYPTED_SECRET); \
             slot 13 is structured -- not arbitrary bytes"
        )
    })
}

fn read_key_file(path: &Path) -> anyhow::Result<[u8; GKS_LEN]> {
    tracing::info!(path = %path.display(), "reading GuestSecretKey blob from --key file");
    let bytes = fs_err::read(path).context("reading --key file")?;
    bytes_to_slot(&bytes, "--key file")
}

async fn read_gks_from_vmgs_file(path: &Path) -> anyhow::Result<[u8; GKS_LEN]> {
    tracing::info!(path = %path.display(), "opening --vmgs file");
    let file = fs_err::OpenOptions::new()
        .read(true)
        .open(path)
        .context("opening --vmgs file")?;
    let disk = Disk::new(
        Vhd1Disk::open_fixed(file.into(), /* read_only */ true)
            .context("opening VMGS file as a VHD")?,
    )
    .context("constructing Disk from VMGS VHD")?;
    read_gks_from_disk(disk).await
}

async fn read_gks_from_disk(disk: Disk) -> anyhow::Result<[u8; GKS_LEN]> {
    let mut vmgs = Vmgs::open(disk, None)
        .await
        .context("parsing VMGS structure")?;
    if vmgs.encrypted() {
        bail!(
            "VMGS file is encrypted; decrypt-serial does not support unlocking encrypted VMGS files. \
             Extract the GuestSecretKey via attestation (or another out-of-band path) and pass it with --key."
        );
    }
    let bytes = vmgs
        .read_file_raw(FileId::GUEST_SECRET_KEY)
        .await
        .context("reading FileId::GUEST_SECRET_KEY from the VMGS")?;
    bytes_to_slot(&bytes, "VMGS GUEST_SECRET_KEY entry")
}

fn bytes_to_slot(bytes: &[u8], source: &str) -> anyhow::Result<[u8; GKS_LEN]> {
    if bytes.is_empty() {
        bail!("{source} is empty; expected up to {GKS_LEN} bytes of GuestSecretKey material");
    }
    if bytes.len() > GKS_LEN {
        bail!(
            "{source} is {} bytes long; the GuestSecretKey is at most {GKS_LEN} bytes",
            bytes.len()
        );
    }
    if bytes.len() < GKS_LEN {
        tracing::warn!(
            len = bytes.len(),
            expected = GKS_LEN,
            "{source} is shorter than the full GuestSecretKey; \
             zero-padding to {GKS_LEN} bytes (matches underhill_attestation behavior)"
        );
    }
    let mut material = [0u8; GKS_LEN];
    material[..bytes.len()].copy_from_slice(bytes);
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use disklayer_ram::ram_disk;
    use pal_async::async_test;
    use vmgs::Vmgs;
    use zerocopy::IntoBytes;

    /// A real, deterministic TPM Import payload (lifted from
    /// `vm/devices/tpm/tpm_lib/src/lib.rs:3023-3054`). Used in
    /// place of the previous `head -c 2048 /dev/urandom`-style
    /// fixtures because slot 13 contents now have to parse as a
    /// valid TPM2 Import payload to be accepted by `parse_gks`.
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

    fn write_temp_key(bytes: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    #[async_test]
    async fn key_file_full_length_with_real_blob() {
        // A full 2048-byte slot containing a real TPM Import blob
        // followed by zero padding round-trips through resolve.
        let mut padded = SAMPLE_IMPORT_BLOB.to_vec();
        padded.resize(GKS_LEN, 0);
        let f = write_temp_key(&padded);
        let parsed = resolve(&KeySource::Key(f.path().to_path_buf()))
            .await
            .unwrap();
        assert!(!parsed.kdf_input.is_empty());
    }

    #[async_test]
    async fn key_file_short_real_blob_is_zero_padded_then_parsed() {
        // A short file (< 2048 bytes) containing exactly the
        // Import payload still parses; the zero padding the
        // resolver applies doesn't disturb the parser.
        let f = write_temp_key(SAMPLE_IMPORT_BLOB);
        let parsed = resolve(&KeySource::Key(f.path().to_path_buf()))
            .await
            .unwrap();
        assert!(!parsed.kdf_input.is_empty());
    }

    #[async_test]
    async fn key_file_garbage_rejected() {
        // The previous behavior was to KDF over arbitrary 2048
        // bytes; now we fail-closed if the bytes don't parse as a
        // TPM Import payload. Use an obviously-invalid TPM2B size
        // (0xffff) for the first field.
        let mut garbage = vec![0xffu8; GKS_LEN];
        garbage[0] = 0xff;
        garbage[1] = 0xff;
        let f = write_temp_key(&garbage);
        let err = resolve(&KeySource::Key(f.path().to_path_buf()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("TPM2 Import payload"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn key_file_empty_rejected_in_read_layer() {
        let f = write_temp_key(&[]);
        let err = read_key_file(f.path()).unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn key_file_oversized_rejected_in_read_layer() {
        let key = vec![0u8; GKS_LEN + 1];
        let f = write_temp_key(&key);
        let err = read_key_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("at most"),
            "unexpected error: {err}"
        );
    }

    async fn make_vmgs_with_gks(secret: &[u8]) -> Disk {
        let disk = ram_disk(4 * 1024 * 1024, false).unwrap();
        let mut vmgs = Vmgs::format_new(disk.clone(), None).await.unwrap();
        let payload = openhcl_attestation_protocol::vmgs::GuestSecretKey {
            guest_secret_key: {
                let mut buf = [0u8; GUEST_SECRET_KEY_MAX_SIZE];
                buf[..secret.len()].copy_from_slice(secret);
                buf
            },
        };
        vmgs.write_file(FileId::GUEST_SECRET_KEY, payload.as_bytes())
            .await
            .unwrap();
        // Drop the in-memory Vmgs so the underlying disk can be re-opened.
        drop(vmgs);
        disk
    }

    #[async_test]
    async fn vmgs_path_round_trip() {
        let disk = make_vmgs_with_gks(SAMPLE_IMPORT_BLOB).await;
        let raw = read_gks_from_disk(disk).await.unwrap();
        let parsed = parse_gks(&raw).expect("GUEST_SECRET_KEY should parse");
        assert!(!parsed.kdf_input.is_empty());
    }

    #[async_test]
    async fn vmgs_path_garbage_blob_rejected() {
        // Non-TPM-Import bytes in the slot: read succeeds, parse
        // fails-closed at the resolver layer.
        let mut garbage = vec![0xffu8; 64];
        garbage[0] = 0xff;
        garbage[1] = 0xff;
        let disk = make_vmgs_with_gks(&garbage).await;
        let raw = read_gks_from_disk(disk).await.unwrap();
        let err = parse_gks(&raw).unwrap_err();
        assert!(
            err.to_string().contains("TPM2 Import payload"),
            "unexpected error: {err:#}"
        );
    }

    #[async_test]
    async fn vmgs_path_missing_gks_errors() {
        let disk = ram_disk(4 * 1024 * 1024, false).unwrap();
        let _ = Vmgs::format_new(disk.clone(), None).await.unwrap();
        let err = read_gks_from_disk(disk).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("reading FileId::GUEST_SECRET_KEY from the VMGS"),
            "unexpected error: {err:#}"
        );
    }
}
