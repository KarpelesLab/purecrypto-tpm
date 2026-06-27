//! `purecrypto-tpm` — a pure-Rust TPM 2.0 stack.
//!
//! This crate speaks the TPM 2.0 command/response wire protocol (TCG *TPM 2.0
//! Library Specification*, Parts 1–4) directly, with no `tpm2-tss`, no C, and
//! no foreign code. The session cryptography it needs — SHA-2 for object
//! Names and `cpHash`/`rpHash`, HMAC for HMAC sessions, KDFa, AES-CFB for
//! parameter encryption — is drawn from the sibling [`purecrypto`] crate.
//!
//! # Layers
//!
//! 1. **Marshalling** ([`marshal`]) — the big-endian [`Marshal`]/[`Unmarshal`]
//!    traits every TPM structure is built from.
//! 2. **Types** ([`types`]) — the TPM constants (`TPM_CC`, `TPM_RC`,
//!    `TPM_ALG_ID`, handles …) and the structure subset this crate uses.
//! 3. **Transport** ([`transport`]) — a [`Transport`](transport::Transport)
//!    trait with two `std` backends: the Linux character device
//!    ([`DeviceTransport`](transport::DeviceTransport)) and the
//!    Microsoft/swtpm simulator socket
//!    ([`SimulatorTransport`](transport::SimulatorTransport)).
//! 4. **Sessions** ([`session`]) — KDFa, HMAC authorization sessions and
//!    command/response parameter encryption.
//! 5. **Commands** ([`commands`]) — typed wrappers (`Startup`, `GetRandom`,
//!    `GetCapability`, `PcrRead`, `CreatePrimary`, `Create`, `Load`,
//!    `Unseal`, …) dispatched through [`Tpm`].
//!
//! # Status
//!
//! Early. The wire codec, the read-only command set, HMAC sessions and a
//! create/load/unseal sealing flow are the initial milestone. Many structures
//! and commands are not yet modelled.
//!
//! # `no_std`
//!
//! The marshalling and session core is `#![no_std]` + `alloc`. The OS
//! transports (and `std::error::Error`) require the default `std` feature;
//! build with `--no-default-features --features alloc-only-consumers` style
//! configs to drive a custom [`Transport`](transport::Transport) on bare
//! metal. (The crate always needs `alloc`.)

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod marshal;
pub mod session;
pub mod transport;
pub mod types;

pub mod commands;

mod crypto;
mod tpm;

pub use error::{Error, Result, TpmRc};
pub use session::Session;
pub use tpm::{Auth, Tpm};
