# purecrypto-tpm

[![CI](https://github.com/KarpelesLab/purecrypto-tpm/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/purecrypto-tpm/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/purecrypto-tpm.svg)](https://crates.io/crates/purecrypto-tpm)
[![docs.rs](https://img.shields.io/docsrs/purecrypto-tpm)](https://docs.rs/purecrypto-tpm)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

// Or a simulator over TCP, for testing without hardware. swtpm's data socket
// (2321) speaks the same mssim framing; start it with `--flags startup-clear`
// so it powers on and runs TPM2_Startup itself, then just connect:
let mut tpm = Tpm::new(SimulatorTransport::connect_default()?);

// The ms-tpm-20-ref / IBM simulator instead drives power over a second
// "platform" socket (2322):
let mut sim = SimulatorTransport::connect_mssim_default()?;
sim.power_on()?;                 // POWER_ON + NV_ON over the platform socket
let mut tpm = Tpm::new(sim);
# Ok::<(), purecrypto_tpm::Error>(())
```

> Note: `/dev/tpm0` and `/dev/tpmrm0` are typically root-only. Use a group/udev
> rule, run elevated, or point at a simulator for unprivileged development:
>
> ```text
> swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
>   --tpmstate dir=$(mktemp -d) --flags not-need-init,startup-clear
> ```

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

## Development

The crate depends on the published `purecrypto` from crates.io. To co-develop
against a local checkout, add a patch to `Cargo.toml` (don't commit it — CI and
`cargo publish` should use the release):

```toml
[patch.crates-io]
purecrypto = { path = "../purecrypto" }
```

Run the full test suite — unit tests plus the simulator integration tests —
against a local swtpm:

```sh
swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --tpmstate dir=$(mktemp -d) --flags not-need-init,startup-clear &
PURECRYPTO_TPM_SIM=127.0.0.1:2321 cargo test
```

Without `PURECRYPTO_TPM_SIM` the integration tests skip themselves, so a bare
`cargo test` runs only the unit tests. CI (`.github/workflows/ci.yml`) runs
fmt/clippy/docs, `no_std` builds, the MSRV check, and the swtpm integration
job; `release-plz` publishes to crates.io.

## License

MIT — see [LICENSE](LICENSE). © 2026 Karpelès Lab Inc.
