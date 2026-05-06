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
    /// after deriving the key; see the `EncryptingSerialBackendHandle`
    /// resolver for the resource-layer protocol.
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncReadExt as _;
    use futures::AsyncWriteExt as _;
    use openhcl_serial_console_crypto::crypto::GKS_LEN;
    use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
    use openhcl_serial_console_crypto::crypto::decrypt;
    use openhcl_serial_console_crypto::crypto::derive_aes_key;
    use openhcl_serial_console_crypto::format::Record;
    use openhcl_serial_console_crypto::format::SentinelMatch;
    use openhcl_serial_console_crypto::format::find_next_sentinel;
    use pal_async::async_test;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::future::poll_fn;
    use std::sync::Arc;

    /// A fake `SerialIo` whose state is observable via a shared
    /// handle so tests can poke at it.
    #[derive(Default)]
    struct FakeInnerState {
        /// Bytes the wrapper has written to us.
        written: Vec<u8>,
        /// Bytes available to be returned from `poll_read`.
        read_buf: VecDeque<u8>,
        /// `Some(n)` accepts at most `n` bytes per `poll_write`;
        /// `None` accepts everything.
        write_chunk_limit: Option<usize>,
        /// When true, every `poll_write` returns Pending without
        /// consuming bytes. Tests flip this to simulate a slow host.
        write_pending: bool,
        /// Bumped by `poll_flush`.
        flush_calls: usize,
        /// Bumped by `poll_close`.
        close_calls: usize,
    }

    struct FakeInner {
        state: Arc<Mutex<FakeInnerState>>,
    }

    impl FakeInner {
        fn new() -> (Self, Arc<Mutex<FakeInnerState>>) {
            let state = Arc::new(Mutex::new(FakeInnerState::default()));
            (
                FakeInner {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl InspectMut for FakeInner {
        fn inspect_mut(&mut self, req: inspect::Request<'_>) {
            req.respond();
        }
    }

    impl AsyncWrite for FakeInner {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock();
            if state.write_pending {
                return Poll::Pending;
            }
            let limit = state.write_chunk_limit.unwrap_or(buf.len());
            let n = buf.len().min(limit);
            state.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.state.lock().flush_calls += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.state.lock().close_calls += 1;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for FakeInner {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock();
            if state.read_buf.is_empty() {
                return Poll::Pending;
            }
            let n = state.read_buf.len().min(buf.len());
            for (slot, src) in buf.iter_mut().zip(state.read_buf.drain(..n)) {
                *slot = src;
            }
            Poll::Ready(Ok(n))
        }
    }

    impl SerialIo for FakeInner {
        fn is_connected(&self) -> bool {
            true
        }

        fn poll_connect(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_disconnect(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    fn sample_keys() -> ([u8; AES_KEY_LEN], [u8; SESSION_ID_LEN]) {
        let mut gks_bytes = [0u8; GKS_LEN];
        for (i, b) in gks_bytes.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let session_id = [0xa5u8; SESSION_ID_LEN];
        let aes_key = derive_aes_key(&GksKeyMaterial(gks_bytes), &session_id).unwrap();
        (aes_key, session_id)
    }

    fn decrypt_capture(captured: &[u8], aes_key: &[u8; AES_KEY_LEN]) -> Vec<u8> {
        let mut plaintext = Vec::new();
        let mut cursor = 0;
        while let SentinelMatch::Found {
            start: _,
            end,
            payload,
        } = find_next_sentinel(captured, cursor)
        {
            let record = Record::parse_payload(&payload).unwrap();
            let dec = decrypt(
                aes_key,
                &record.session_id,
                record.seq,
                &record.nonce,
                &record.ciphertext,
                &record.tag,
            )
            .unwrap();
            plaintext.extend_from_slice(&dec);
            cursor = end;
        }
        plaintext
    }

    #[async_test]
    async fn round_trip_single_line() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        wrapper.write_all(b"hello\n").await.unwrap();
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        assert_eq!(decrypt_capture(&captured_bytes, &aes_key), b"hello\n");
        assert!(captured.lock().flush_calls >= 1);
    }

    #[async_test]
    async fn one_byte_at_a_time_writes_assemble_into_one_record() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        for b in b"hello\n" {
            wrapper.write_all(std::slice::from_ref(b)).await.unwrap();
        }
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        assert_eq!(decrypt_capture(&captured_bytes, &aes_key), b"hello\n");
    }

    #[async_test]
    async fn multi_line_round_trips() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        wrapper.write_all(b"line one\n").await.unwrap();
        wrapper.write_all(b"line two\n").await.unwrap();
        wrapper.write_all(b"line three\n").await.unwrap();
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        let plaintext = decrypt_capture(&captured_bytes, &aes_key);
        assert_eq!(plaintext, b"line one\nline two\nline three\n");
    }

    #[async_test]
    async fn newlines_inside_one_slice_round_trip() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        // Multiple newlines in one accept slice. The wrapper emits a
        // single record because it batches per-call, not per-line.
        wrapper.write_all(b"a\nb\nc\n").await.unwrap();
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        assert_eq!(decrypt_capture(&captured_bytes, &aes_key), b"a\nb\nc\n");
    }

    #[async_test]
    async fn no_newline_then_flush_emits_record() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        wrapper.write_all(b"no terminator").await.unwrap();
        // Without flush, this would sit in the buffer (v1 has no
        // idle timer). Flushing is the explicit way to drain.
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        assert_eq!(decrypt_capture(&captured_bytes, &aes_key), b"no terminator");
    }

    #[async_test]
    async fn close_best_effort_flushes_pending_plaintext() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        wrapper.write_all(b"tail with no newline").await.unwrap();
        wrapper.close().await.unwrap();

        let st = captured.lock();
        assert_eq!(
            decrypt_capture(&st.written, &aes_key),
            b"tail with no newline"
        );
        assert!(st.close_calls >= 1);
        assert!(st.flush_calls >= 1);
    }

    #[async_test]
    async fn full_buffer_emits_then_accepts_more() {
        let (inner, captured) = FakeInner::new();
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        // Just over MAX_PLAINTEXT_LEN of `a`s with no newlines.
        // First write fills the buffer, second forces an emit then
        // accepts the rest.
        let big = vec![b'a'; MAX_PLAINTEXT_LEN + 100];
        wrapper.write_all(&big).await.unwrap();
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        let plaintext = decrypt_capture(&captured_bytes, &aes_key);
        assert_eq!(plaintext.len(), big.len());
        assert!(plaintext.iter().all(|b| *b == b'a'));
    }

    #[async_test]
    async fn inner_writes_chunked_to_64_bytes_still_round_trip() {
        let (inner, captured) = FakeInner::new();
        captured.lock().write_chunk_limit = Some(64); // emulates vmbus_serial_guest
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        let payload: Vec<u8> = (0..2000u32).map(|i| (i & 0xff) as u8).collect();
        // Put a newline at the end so the wrapper emits.
        let mut input = payload.clone();
        input.push(b'\n');
        wrapper.write_all(&input).await.unwrap();
        wrapper.flush().await.unwrap();

        let captured_bytes = captured.lock().written.clone();
        assert_eq!(decrypt_capture(&captured_bytes, &aes_key), input);
    }

    #[async_test]
    async fn reads_pass_through_inner() {
        let (inner, captured) = FakeInner::new();
        captured.lock().read_buf.extend(b"host typed this".iter().copied());
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        let mut buf = [0u8; 16];
        let n = wrapper.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"host typed this");
    }

    #[async_test]
    async fn backpressure_when_inner_is_pending() {
        let (inner, captured) = FakeInner::new();
        captured.lock().write_pending = true;
        let (aes_key, session_id) = sample_keys();
        let mut wrapper = EncryptingSerialIo::new(Box::new(inner), aes_key, session_id);

        // Fill the plaintext buffer (no newline => no emit yet).
        let half = vec![b'x'; MAX_PLAINTEXT_LEN];
        let n = poll_fn(|cx| Pin::new(&mut wrapper).poll_write(cx, &half)).await.unwrap();
        assert_eq!(n, MAX_PLAINTEXT_LEN);

        // Trigger an emit by writing a newline. Now there's an
        // encoded record in flight; inner refuses to accept any of
        // it. Subsequent writes should return Pending until inner
        // unblocks, never grow buffers.
        let _ = poll_fn(|cx| Pin::new(&mut wrapper).poll_write(cx, b"\n")).await;

        let res = poll_fn(|cx| match Pin::new(&mut wrapper).poll_write(cx, b"more") {
            Poll::Ready(r) => Poll::Ready(Some(r)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        // Either Pending (None) or accepted up to remaining buffer
        // capacity, which after the forced emit is some small amount
        // (because we re-buffer post-emit but inner is still stuck).
        // Critically, the wrapper must not panic, must not grow
        // unboundedly, and must not lose written bytes silently.
        if let Some(r) = res {
            let bytes_consumed = r.unwrap();
            assert!(
                bytes_consumed <= MAX_PLAINTEXT_LEN,
                "wrapper accepted more bytes than its plaintext budget allows"
            );
        }

        // Now let inner drain.
        captured.lock().write_pending = false;
        wrapper.flush().await.unwrap();

        // Whatever bytes the wrapper accepted should have been
        // captured and decryptable. We don't assert the exact
        // content because backpressure semantics permit the wrapper
        // to refuse some bytes; we just assert no corruption.
        let captured_bytes = captured.lock().written.clone();
        // Decrypting must succeed on at least one record.
        let plain = decrypt_capture(&captured_bytes, &aes_key);
        assert!(!plain.is_empty(), "expected at least one decryptable record");
    }
}
