// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SerialIo` adapter that encrypts the L1 guest's COM port writes
//! before they leave VTL2 (OpenHCL).
//!
//! The host (and the Hyper-V root partition) sees only encrypted
//! records on the wire; VTL2 stays inside the trust boundary. The
//! wire format and key derivation live in the
//! [`openhcl_serial_console_crypto`] crate; this crate is solely the
//! VTL2-side plumbing that wraps an inner [`serial_core::SerialIo`]
//! and routes guest writes through AES-256-GCM before forwarding
//! them to the inner backend.
//!
//! See the project Guide page
//! `Guide/src/reference/openhcl/diag/decrypt_serial.md` for the
//! end-to-end story.
//!
//! The crate is currently Linux-only; see the
//! [`openhcl_serial_console_crypto`] crate docs for why.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

mod handle;
mod io;
mod resolver;

pub use handle::EncryptingSerialBackendHandle;
pub use io::EncryptingSerialIo;
pub use resolver::EncryptingSerialResolver;
