// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource-layer plumbing: the [`EncryptingSerialBackendHandle`]
//! mesh-payload type and its [`ResourceId`] registration.

use mesh::MeshPayload;
use openhcl_serial_console_crypto::crypto::GKS_LEN;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::kind::SerialBackendHandle;

/// Wrap an inner [`SerialBackendHandle`] resource so that all writes
/// flowing through it (i.e., L1-guest-to-host bytes for an OpenHCL
/// CVM's COM port) are encrypted on the wire.
///
/// Construction is the responsibility of the wiring code in
/// `underhill_core::worker`: that code captures the GuestSecretKey
/// returned by `initialize_platform_security`, decides whether
/// encryption applies based on isolation type, and constructs one of
/// these handles per affected COM port.
///
/// **GKS lifetime.** This handle carries the raw 2048-byte
/// GuestSecretKey across mesh during resource resolution. The
/// resolver derives the per-session AES-256-GCM key as soon as it
/// receives the handle and immediately drops the GKS bytes; the
/// long-lived `EncryptingSerialIo` only retains the derived key plus
/// the per-port `session_id`. Do not store this handle longer than
/// strictly necessary, and do not log or inspect its contents.
#[derive(MeshPayload)]
pub struct EncryptingSerialBackendHandle {
    /// The serial backend whose writes will be encrypted.
    ///
    /// Resolved recursively by the encrypting resolver; the recovered
    /// `Box<dyn SerialIo>` becomes the wrapper's inner sink.
    pub inner: Resource<SerialBackendHandle>,
    /// The 2048-byte GuestSecretKey blob from `FileId::GUEST_SECRET_KEY`.
    /// Only used during resolution to derive a per-port AES key.
    pub gks: [u8; GKS_LEN],
}

impl ResourceId<SerialBackendHandle> for EncryptingSerialBackendHandle {
    const ID: &'static str = "openhcl-encrypted-serial-v1";
}
