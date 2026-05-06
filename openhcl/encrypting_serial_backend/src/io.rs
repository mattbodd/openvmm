// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The `EncryptingSerialIo<Box<dyn SerialIo>>` adapter and its
//! `AsyncRead`/`AsyncWrite`/`SerialIo` implementations.

use futures::io::AsyncRead;
use futures::io::AsyncWrite;
use inspect::InspectMut;
use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use serial_core::SerialIo;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use vm_resource::Resource;
use vm_resource::kind::SerialBackendHandle;

/// `SerialIo` adapter that AES-256-GCM-encrypts every write before
/// forwarding it to an inner `SerialIo`. Reads pass through verbatim.
///
/// The wrapper batches plaintext bytes into records bounded by
/// [`MAX_PLAINTEXT_LEN`], emitting one record on any of:
/// `\n` in the buffered bytes, full plaintext buffer, `poll_flush`,
/// or `poll_close`. Tail data with no newline that is followed by a
/// quiet period stays buffered until the next call; an idle-flush
/// timer is intentionally left for a v2 follow-up (see the producer
/// plan for rationale).
///
/// **Backpressure.** Two fixed buffers (`plaintext_pending` of at
/// most `MAX_PLAINTEXT_LEN`, plus one in-flight encoded record). When
/// both are full, `poll_write` returns `Pending` rather than dropping
/// or growing.
pub struct EncryptingSerialIo {
    inner: Box<dyn SerialIo>,
    aes_key: [u8; AES_KEY_LEN],
    session_id: [u8; SESSION_ID_LEN],
    seq: u64,
    plaintext_pending: Vec<u8>,
    encoded_pending: Vec<u8>,
    encoded_offset: usize,
}

impl EncryptingSerialIo {
    /// Wrap `inner` so that every write is AES-256-GCM encrypted into
    /// a v1 record using the supplied per-port `aes_key` and
    /// `session_id`.
    ///
    /// `aes_key` should be the result of
    /// `openhcl_serial_console_crypto::crypto::derive_aes_key`. The
    /// caller is expected to drop the source GKS bytes immediately
    /// after deriving the key; see [`crate::handle`] for the
    /// resource-layer protocol.
    pub fn new(
        inner: Box<dyn SerialIo>,
        aes_key: [u8; AES_KEY_LEN],
        session_id: [u8; SESSION_ID_LEN],
    ) -> Self {
        Self {
            inner,
            aes_key,
            session_id,
            seq: 0,
            plaintext_pending: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            encoded_pending: Vec::new(),
            encoded_offset: 0,
        }
    }

    /// Encrypt `plaintext_pending` into `encoded_pending` (with a
    /// trailing newline so captured streams stay readable when
    /// records are interleaved with plaintext).
    fn emit_record(&mut self) -> io::Result<()> {
        debug_assert!(self.encoded_pending.is_empty());
        debug_assert!(!self.plaintext_pending.is_empty());

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|e| io::Error::other(format!("getrandom for nonce: {e}")))?;

        let (ciphertext, tag) = encrypt(
            &self.aes_key,
            &self.session_id,
            self.seq,
            &nonce,
            &self.plaintext_pending,
        )
        .map_err(io::Error::other)?;

        let record = Record {
            session_id: self.session_id,
            seq: self.seq,
            nonce,
            ciphertext,
            tag,
        };
        let mut s = record.encode_to_string();
        s.push('\n');
        self.encoded_pending = s.into_bytes();
        self.encoded_offset = 0;
        self.plaintext_pending.clear();
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }

    /// Drain `encoded_pending` into the inner backend.
    fn poll_drain_encoded(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.encoded_offset < self.encoded_pending.len() {
            let remaining = &self.encoded_pending[self.encoded_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Poll::Ready(Ok(n)) => {
                    self.encoded_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.encoded_pending.clear();
        self.encoded_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl InspectMut for EncryptingSerialIo {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("seq", self.seq)
            .field("plaintext_pending_bytes", self.plaintext_pending.len())
            .field(
                "encoded_pending_bytes",
                self.encoded_pending.len() - self.encoded_offset,
            )
            .field_mut("inner", &mut self.inner);
    }
}

impl AsyncWrite for EncryptingSerialIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        // Drain any in-flight encoded record first. If we cannot make
        // progress AND the plaintext buffer is full, we must stall.
        if me.encoded_offset < me.encoded_pending.len() {
            match me.poll_drain_encoded(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if me.plaintext_pending.len() >= MAX_PLAINTEXT_LEN {
                        return Poll::Pending;
                    }
                    // Otherwise fall through and accept some bytes
                    // into the remaining plaintext capacity.
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // If the plaintext buffer is full and we don't have an
        // encoded record in flight, force-emit and stall to let the
        // inner backend drain.
        if me.plaintext_pending.len() >= MAX_PLAINTEXT_LEN {
            debug_assert!(me.encoded_pending.is_empty());
            me.emit_record()?;
            let _ = me.poll_drain_encoded(cx);
            return Poll::Pending;
        }

        let space = MAX_PLAINTEXT_LEN - me.plaintext_pending.len();
        let to_accept = buf.len().min(space);
        let accepted = &buf[..to_accept];
        me.plaintext_pending.extend_from_slice(accepted);

        // Trigger an emit on newline OR full buffer, but only if no
        // record is currently in flight (we don't queue more than
        // one).
        let saw_newline = accepted.contains(&b'\n');
        let now_full = me.plaintext_pending.len() >= MAX_PLAINTEXT_LEN;
        if (saw_newline || now_full) && me.encoded_pending.is_empty() {
            me.emit_record()?;
            // Best-effort drain; OK if it goes Pending.
            let _ = me.poll_drain_encoded(cx);
        }

        Poll::Ready(Ok(to_accept))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        if !me.plaintext_pending.is_empty() && me.encoded_pending.is_empty() {
            me.emit_record()?;
        }

        match me.poll_drain_encoded(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        if !me.plaintext_pending.is_empty() && me.encoded_pending.is_empty() {
            me.emit_record()?;
        }

        match me.poll_drain_encoded(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        match Pin::new(&mut me.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut me.inner).poll_close(cx)
    }
}

impl AsyncRead for EncryptingSerialIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_read_vectored(cx, bufs)
    }
}

impl SerialIo for EncryptingSerialIo {
    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_connect(cx)
    }

    fn poll_disconnect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_disconnect(cx)
    }
}

// Match the existing pattern from
// `vmbus_serial_guest::VmbusSerialDriver`
// (`vm/devices/serial/vmbus_serial_guest/src/lib.rs:186-189`):
// underhill never converts a resolved backend back into a `Resource`,
// so panic if the path is ever exercised.
impl From<EncryptingSerialIo> for Resource<SerialBackendHandle> {
    fn from(_value: EncryptingSerialIo) -> Self {
        unimplemented!(
            "EncryptingSerialIo cannot be converted back into a Resource; \
             VTL2 producer wiring does not need this path"
        )
    }
}
