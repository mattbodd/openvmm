# decrypt-serial

`decrypt-serial` is a host-side dev/debug tool for decrypting serial console
output that has been emitted by OpenHCL VTL2 in the **encrypted serial
console v1** wire format.

The producer is the OpenHCL paravisor itself: when an L1 guest of a CVM
(SNP, TDX, or VBS) writes to its COM1 or COM2, VTL2 transparently encrypts
the bytes via `encrypting_serial_backend` before they leave the trust
boundary. The host (and even the Hyper-V root partition) only sees
encrypted records on the wire; only someone holding the GuestSecretKey
(`FileId::GUEST_SECRET_KEY` in the VMGS) can recover the plaintext, and
this tool is how they do it.

The crate currently only builds on Linux, because the underlying
`crypto::kdf::kbkdf_hmac_sha256` primitive in the workspace `crypto` crate
is implemented via the Unix-only `openssl_kdf` crate. On Windows hosts, run
the tool from WSL2.

## Wire format (v1)

Each encrypted record is wrapped in a printable ASCII sentinel so that
records can be interleaved with plaintext lines on the same console
without binary corruption:

```
[[OHENC v1 <base64-payload>]]
```

The base64 payload (standard alphabet, padding required, no whitespace,
no line wrapping) decodes to the binary record:

| Offset  | Size | Field          | Notes                                                                  |
| ------: | ---: | -------------- | ---------------------------------------------------------------------- |
|       0 |   16 | `session_id`   | Random per-session identifier produced once per producer startup.      |
|      16 |    8 | `seq` (u64 LE) | Monotonic sequence number within the session.                          |
|      24 |   12 | `nonce`        | AES-256-GCM nonce. Producer guarantees uniqueness within `session_id`. |
|      36 |    N | `ciphertext`   | Encrypted plaintext bytes. `N ≤ 4096`.                                 |
|  36 + N |   16 | `tag`          | AES-256-GCM authentication tag.                                        |

The AES-GCM AAD bound to every record is:

```
"OpenHCL encrypted serial console v1 AES-256-GCM\0"
    || session_id (16 bytes)
    || seq (u64 LE)
```

Tampering with the version domain string, the `session_id`, or the `seq`
will fail tag verification.

## Per-session keys

The AES-256-GCM key is derived per-`session_id` from the 2048-byte
`GUEST_SECRET_KEY` (GKS) blob in the VMGS:

```
aes_key = KBKDF-HMAC-SHA-256(
    key        = GKS bytes (2048),
    context    = b"OpenHCL encrypted serial console v1 AES-256-GCM key",
    salt       = session_id (16 bytes),
    output_len = 32,
)
```

Per-session keys mean the producer is free to use either random or counter
nonces within a session: nonce uniqueness only has to hold per-session,
not for the entire VM lifetime. The decryptor caches the derivation
result per `session_id` so it does not re-run the KDF for every record.

The shared library crate `openhcl_serial_console_crypto` (`openhcl/openhcl_serial_console_crypto/`)
owns the wire-format and key-derivation code. The eventual producer in
OpenHCL VTL2 will depend on the same crate, ensuring byte-for-byte
compatibility.

## Usage

```text
decrypt-serial --input <PATH> [--output <PATH>] (--key <PATH> | --vmgs <PATH>) [--strict]
```

The most common flow extracts the GKS from the VM's VMGS file with
`vmgstool` and then feeds it to `decrypt-serial`:

```sh
# 1. Extract GUEST_SECRET_KEY (FileId 13) out of the VMGS file.
vmgstool dump --filepath my_vm.vmgs --fileid GUEST_SECRET_KEY \
              --datapath gks.bin --raw-stdout

# 2. Decrypt a captured serial log.
decrypt-serial --key gks.bin --input com3-capture.txt
```

If the VMGS file is plaintext (i.e. not encrypted at rest), you can pass
it directly and skip the manual extraction step:

```sh
decrypt-serial --vmgs my_vm.vmgs --input com3-capture.txt
```

Encrypted VMGS files are explicitly **not** supported by `--vmgs`;
unlocking those requires attestation, which is out of scope for a host
debug tool. The tool detects this case up front and produces a friendly
error pointing back at the `--key` workflow.

### Behavior summary

- **Plaintext passthrough.** Bytes that appear outside any sentinel are
  copied through to the output verbatim, so a capture that starts with
  plaintext boot output and switches to encrypted records once the GKS
  becomes available decrypts cleanly into a single readable stream.
- **Decrypt failures (default).** Tampered or malformed records are
  reported with an inline `<<decrypt failed offset=N reason=...>>`
  marker, and the scan continues. The reported offset is the byte
  position of the failed sentinel in the input file (the `seq` field is
  attacker-controlled on a failed record so we deliberately do not
  surface it).
- **Decrypt failures (`--strict`).** The first malformed sentinel or
  decrypt failure aborts the run with a non-zero exit code.
- **Sequence-gap warnings.** Once at least one record from a given
  session has authenticated successfully, missing or out-of-order
  sequence numbers within that session are reported as warnings on
  stderr.
- **Logging.** Tracing output goes strictly to stderr so the decrypted
  plaintext on stdout is never corrupted.

## Manual round-trip

To verify the tool works end-to-end without a real producer or VM, the
crate ships a Cargo example called `encrypt_fixture` that produces v1
records from arbitrary plaintext using the same library code the
decryptor consumes. **It is a developer aid only — not a sanctioned
encrypt CLI.** The eventual VTL2 producer will live in OpenHCL itself.

```sh
# Generate a random 2 KB GKS for testing.
head -c 2048 /dev/urandom > gks.bin

# Encrypt some plaintext.
cargo run --example encrypt_fixture -p decrypt-serial -- \
    --key gks.bin --input my.log --output capture.txt

# Decrypt and verify.
cargo run -p decrypt-serial -- \
    --key gks.bin --input capture.txt --output recovered.log

diff my.log recovered.log
```

## When the producer ships

The follow-up PR that adds the VTL2 producer side should:

1. Take a dependency on `openhcl_serial_console_crypto` to inherit the
   wire format and key derivation.
2. Generate a fresh random 16-byte `session_id` once at startup, after
   the VMGS unlock makes the GKS available.
3. Emit framed records on COM3 (or wherever the encrypted serial sink
   lives) using the format spec above.
4. Add a petri/VMM test that boots a VM with the producer enabled,
   captures the serial output to a file, runs `decrypt-serial` against
   it, and asserts the recovered plaintext matches the expected
   in-guest log lines.

## Producer side

The encryption is performed by the **`openhcl/encrypting_serial_backend`
crate**, a `SerialIo` adapter that wraps the L1 guest's vmbus serial
backends in VTL2 and AES-256-GCM-encrypts every guest write before
forwarding it to the host. Reads (host → guest input) pass through
unchanged.

### Which COM ports get wrapped

The wrapper is inserted at the resource layer in
`openhcl/underhill_core/src/worker.rs`, around the existing
`vmbus_serial_guest::OpenVmbusSerialGuestConfig::open(...)` calls. It
covers **the L1 guest's COM1 and COM2 only** — i.e. the L1 guest's
`/dev/ttyS0` and `/dev/ttyS1`. Concretely, in OpenHCL terms:

| PC name (Hyper-V / spec) | Linux device (1-VM POV) | What it is | Encrypted? |
|---|---|---|---|
| **COM1** | L1 guest's `/dev/ttyS0` | L1 guest console | **Yes (this PR)** |
| **COM2** | L1 guest's `/dev/ttyS1` | L1 guest auxiliary | **Yes (this PR)** |
| **COM3** | VTL2 paravisor's `/dev/ttyS2` | VTL2's own kernel + underhill console (printk → IO port 0x3E8 → host) | No (different code path; see "Out of scope" below) |
| **COM4** | unused | — | No |

(There is no COM0; PC numbering starts at 1. If you've seen the L1
guest say "I'm using COM0/COM1," that almost always means
`/dev/ttyS0` + `/dev/ttyS1`, which are PC COM1 + COM2.)

### When encryption is on

The encrypting wrapper is enabled **automatically** for any VM with
isolation type SNP, TDX, or VBS. There is no host-controllable flag
to disable it — the host is untrusted in those scenarios, so a
host-side disable would defeat the purpose. Non-CVMs see no behavior
change: the existing plaintext serial flow is unaffected.

If a CVM has serial configured but the GKS is missing (suppressed
attestation, missing VMGS entry, etc.), the affected L1 COM port is
**disabled entirely** and a `tracing::error!(CVM_ALLOWED, ...)` is
emitted on the underhill console. We never silently fall back to
plaintext on a CVM. The VM still boots; the operator can fix VMGS
provisioning and reboot.

### Out of scope (still plaintext after this PR)

- **The VTL2 paravisor's own console output** (`/dev/ttyS2` inside
  VTL2 = PC COM3 = host capture file `openhcl` in petri). underhill's
  `tracing` events take a different path (`KmsgWriter` → `/dev/kmsg` →
  kernel printk → IO port 0x3E8 → host emulator), bypassing
  `SerialIo` entirely. Encrypting that path would need a separate
  follow-up (kernel-side change, or a `/dev/kmsg`-reading userspace
  daemon with `console=ttynull`).
- **L1 guest input** (host → guest reads). The host has no key, so
  there's nothing to encrypt; the wrapper passes reads through
  verbatim.
- **Key rotation** mid-VM-lifetime. The per-port `session_id` is
  fixed for the wrapper's lifetime, but the decryptor already handles
  multi-session captures, so a future producer enhancement is
  format-compatible.

### Test-only force knob

For non-CVM dev environments — including the future petri test — the
wrapper can be force-enabled via a kernel cmdline / env var on the
underhill process:

```
OPENHCL_TEST_ONLY_FORCE_ENCRYPTED_SERIAL=1
```

When set on a non-CVM, the wrapper is enabled and a loud
`tracing::warn!(CVM_ALLOWED, ...)` is emitted. **This knob is
strictly enable-only**: there is no corresponding flag to *disable*
encryption for a real CVM.

To exercise it manually with petri / OpenVMM:

```text
.with_openhcl_command_line("OPENHCL_TEST_ONLY_FORCE_ENCRYPTED_SERIAL=1")
```

### Manual end-to-end recipe with a real OpenHCL VM

This is what the eventual petri test will automate; you can run it by
hand today to sanity-check a build. From a Linux OpenHCL host:

```sh
# 1. Provision a VMGS file with a known GuestSecretKey.
head -c 2048 /dev/urandom > /tmp/gks.bin
vmgstool create   --filepath /tmp/test.vmgs
vmgstool write    --filepath /tmp/test.vmgs \
                  --fileid   GUEST_SECRET_KEY \
                  --datapath /tmp/gks.bin

# 2. Boot OpenHCL with a Linux L1 guest, the force knob, the VMGS
#    above, and capture the L1 COM1 stream to a file.
openvmm \
    ... your usual OpenHCL launch args ... \
    --openhcl-cmdline OPENHCL_TEST_ONLY_FORCE_ENCRYPTED_SERIAL=1 \
    --vmgs /tmp/test.vmgs \
    --serial0 file:/tmp/com1-capture.txt

# 3. Have the L1 guest write some plaintext to its COM1.
#    (e.g. via the guest's /etc/inittab, or a serial getty, or
#     "echo hello > /dev/ttyS0" once the guest is up).

# 4. After shutdown / capture window, decrypt the captured stream.
decrypt-serial --vmgs /tmp/test.vmgs --input /tmp/com1-capture.txt
# Expected: the guest's plaintext, with any pre-attestation boot
# bytes (which are not encrypted yet) passed through verbatim.
```

If the recovered plaintext matches what the guest wrote, the
producer + decryptor + wire format are working end-to-end. This is
the same flow the `examples/encrypt_fixture` round-trip exercises in
isolation; the only added dimension here is "real serial transport
through vmbus + COM1 emulation."
