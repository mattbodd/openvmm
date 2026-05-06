// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resolver that wires [`EncryptingSerialBackendHandle`] into the
//! `serial_core` resource framework.

use crate::handle::EncryptingSerialBackendHandle;
use crate::io::EncryptingSerialIo;
use anyhow::Context as _;
use async_trait::async_trait;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use serial_core::resources::ResolveSerialBackendParams;
use serial_core::resources::ResolvedSerialBackend;
use vm_resource::AsyncResolveResource;
use vm_resource::ResourceResolver;
use vm_resource::declare_static_async_resolver;
use vm_resource::kind::SerialBackendHandle;

/// Static resolver for [`EncryptingSerialBackendHandle`]. Register
/// this in your resource registry alongside the other serial
/// backend resolvers (e.g. in `openhcl/openvmm_hcl_resources`).
pub struct EncryptingSerialResolver;

declare_static_async_resolver!(
    EncryptingSerialResolver,
    (SerialBackendHandle, EncryptingSerialBackendHandle)
);

#[async_trait]
impl AsyncResolveResource<SerialBackendHandle, EncryptingSerialBackendHandle>
    for EncryptingSerialResolver
{
    type Output = ResolvedSerialBackend;
    type Error = anyhow::Error;

    async fn resolve(
        &self,
        resolver: &ResourceResolver,
        rsrc: EncryptingSerialBackendHandle,
        input: ResolveSerialBackendParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        // Recursively resolve the inner serial backend. This
        // consumes the input (including the Box<dyn Driver>); we do
        // not need the driver locally because the v1 wrapper has no
        // background tasks.
        let inner = resolver
            .resolve(rsrc.inner, input)
            .await
            .context("resolving inner serial backend for encrypting wrapper")?;
        let inner_io = inner.0.into_io();

        // Generate a fresh per-port session_id, derive the AES key,
        // and drop the GKS bytes immediately so the long-lived IO
        // does not retain them.
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id)
            .map_err(|e| anyhow::anyhow!("generating per-port session_id: {e}"))?;

        let gks = GksKeyMaterial(rsrc.gks);
        let aes_key = derive_aes_key(&gks, &session_id)
            .context("deriving per-port AES-256-GCM key from GKS")?;
        // Drop the GKS bytes immediately. `GksKeyMaterial` has no
        // `Drop` impl (and clippy correctly notes this is just a
        // lifetime contraction rather than a zeroize), but making
        // the discard explicit guards future refactors against
        // accidentally retaining the secret past key derivation.
        #[expect(clippy::drop_non_drop, reason = "explicit lifetime contraction for the secret GKS bytes")]
        drop(gks);

        let wrapper = EncryptingSerialIo::new(inner_io, aes_key, session_id);
        Ok(wrapper.into())
    }
}
