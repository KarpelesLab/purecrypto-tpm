# purecrypto-tpm

A **pure-Rust TPM 2.0 stack**. It speaks the TPM 2.0 command/response wire
protocol (TCG *TPM 2.0 Library Specification*, Parts 1–4) **directly** — no
`tpm2-tss`, no C, no foreign code. The session cryptography it needs (object
Names, HMAC sessions, KDFa, AES-CFB parameter encryption) is drawn from the
sibling [`purecrypto`](../purecrypto) crate, keeping the whole stack
foreign-code-free.

> **Status: early.** The wire codec, the read-only command set, HMAC
> authorization sessions and a create/load/unseal sealing flow are implemented
> and unit-tested. Salted sessions, parameter *encryption*, policy sessions,
> NV storage, quoting/attestation and persistent objects are not yet wired in.
> See [Roadmap](#roadmap).

## Design

Built bottom-up, each layer a module:

| Layer | Module | What it is |
| ----- | ------ | ---------- |
| Marshalling | `marshal` | Big-endian `Marshal`/`Unmarshal` traits + a bounds-checked `Reader`; `TPM2B` length-prefixing. |
| Types | `types` | `TPM_CC`/`TPM_RC`/`TPM_ALG_ID`/handles/`TPMA_*` constants and the modelled `TPM2B_*`/`TPMT_*`/`TPMS_*` structures. |
| Transport | `transport` | A `Transport` trait with two `std` backends: the Linux character device and the MS/swtpm simulator socket. |
| Crypto | (internal) | SHA-2/HMAC dispatched by algorithm id over `purecrypto`, plus **KDFa** and the AES-CFB transform. |
| Sessions | `session` | KDFa session-key derivation and HMAC authorization with rolling nonces (command HMAC + response HMAC verification). |
| Commands | `commands` | Typed wrappers (`startup`, `get_random`, `get_capability`, `pcr_read`, `create_primary`, `create`, `load`, `unseal`, …) on `Tpm`. |

### `no_std`

The marshalling and session core is `#![no_std]` + `alloc`. The OS transports
require the default `std` feature; drive a custom `Transport` for bare-metal or
test use.

## Transports

```rust
use purecrypto_tpm::Tpm;
use purecrypto_tpm::transport::{DeviceTransport, SimulatorTransport};

// Real hardware via the in-kernel resource manager (needs access to the device).
let mut tpm = Tpm::new(DeviceTransport::open_default()?);

// Or the Microsoft / swtpm simulator over TCP, for testing without hardware:
let mut sim = SimulatorTransport::connect_default()?;
sim.power_on()?;                 // power + NV signals
let mut tpm = Tpm::new(sim);
# Ok::<(), purecrypto_tpm::Error>(())
```

> Note: `/dev/tpm0` and `/dev/tpmrm0` are typically root-only. Use a group/udev
> rule, run elevated, or point at a simulator (`swtpm socket --tpm2 --server
> type=tcp,port=2321 ...`) for unprivileged development.

## Sealing example

Seal a secret to a TPM-resident storage parent and unseal it again,
authorizing every step with an HMAC session:

```rust
use purecrypto_tpm::{Auth, Tpm};
use purecrypto_tpm::types::constants::{Alg, rh, su};
use purecrypto_tpm::types::handles::Handle;
use purecrypto_tpm::types::structures::{Buffer, Public, SensitiveCreate};

# fn demo(mut tpm: Tpm<impl purecrypto_tpm::transport::Transport>) -> Result<(), purecrypto_tpm::Error> {
tpm.startup(su::CLEAR).ok(); // ignore "already initialised"

// Restricted ECC storage parent under the owner hierarchy (empty owner auth).
let parent_tmpl = Public::ecc_storage_parent(Alg::SHA256);
let parent = tpm.create_primary(
    Handle(rh::OWNER),
    &SensitiveCreate::default(),
    &parent_tmpl,
    &mut Auth::Password(b""),
)?;

// Seal a secret under that parent, protected by its own auth value.
let mut sealed = SensitiveCreate::default();
sealed.user_auth = Buffer::from(&b"seal-pw"[..]);
sealed.data = Buffer::from(&b"my secret"[..]);
let blob = tpm.create(
    parent.handle,
    parent.name.as_slice(),
    &sealed,
    &Public::sealed_data(Alg::SHA256),
    &mut Auth::Password(b""),
)?;

// Load and unseal it — this time over an HMAC session.
let obj = tpm.load(parent.handle, parent.name.as_slice(), &blob.private, &blob.public,
    &mut Auth::Password(b""))?;
let mut sess = tpm.start_hmac_session(Alg::SHA256)?;
let secret = tpm.unseal(
    obj.handle,
    obj.name.as_slice(),
    &mut Auth::Session { session: &mut sess, auth_value: b"seal-pw" },
)?;
assert_eq!(secret, b"my secret");

tpm.flush_context(obj.handle)?;
tpm.flush_context(parent.handle)?;
tpm.flush_context(sess.handle)?;
# Ok(()) }
```

## Roadmap

- Salted sessions (ECDH salt to the EK/SRK) and command/response parameter
  encryption (the AES-CFB primitive is already in place).
- Policy sessions (`PolicyPCR`, `PolicySecret`, …) and policy-gated objects.
- NV storage, persistent objects (`EvictControl`), quoting/attestation.
- RSA storage parents and a richer `TPMT_PUBLIC` parser.
- Integration tests against `swtpm` in CI.

## License

MIT — see [LICENSE](LICENSE). © 2026 Karpelès Lab Inc.
