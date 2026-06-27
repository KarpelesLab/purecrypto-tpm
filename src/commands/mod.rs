//! Typed TPM command wrappers.
//!
//! Each command is a method on [`Tpm`](crate::Tpm), grouped into submodules by
//! area: [`misc`] (startup, randomness, capability), [`pcr`] (PCR read/extend),
//! [`session`] (start/flush authorization sessions) and [`object`] (the
//! create / load / unseal object lifecycle). The methods marshal the parameter
//! area, call [`Tpm::run`](crate::Tpm), and unmarshal the reply into the result
//! types defined here.

use crate::types::handles::Handle;
use crate::types::structures::Buffer;

pub mod misc;
pub mod object;
pub mod pcr;
pub mod session;

/// The outcome of `TPM2_CreatePrimary`: the loaded primary's transient handle,
/// its Name, and the public area (kept verbatim for callers that want it).
#[derive(Clone, Debug)]
pub struct CreatePrimaryResult {
    /// Transient handle of the loaded primary object.
    pub handle: Handle,
    /// The object's Name (`nameAlg || H(public)`), needed to authorize it with
    /// an HMAC session.
    pub name: Buffer,
    /// The `TPMT_PUBLIC` bytes (inner, unprefixed) the TPM returned.
    pub public: Buffer,
}

/// The outcome of `TPM2_Create`: the wrapped private blob and matching public
/// area, the pair you re-`Load` under the same parent.
#[derive(Clone, Debug)]
pub struct CreateResult {
    /// `TPM2B_PRIVATE` inner bytes — the parent-encrypted sensitive blob.
    pub private: Buffer,
    /// `TPM2B_PUBLIC` inner bytes — the object's public area.
    pub public: Buffer,
}

/// The outcome of `TPM2_Load`: the loaded object's transient handle and Name.
#[derive(Clone, Debug)]
pub struct LoadResult {
    /// Transient handle of the loaded object.
    pub handle: Handle,
    /// The object's Name.
    pub name: Buffer,
}

/// The outcome of `TPM2_PCR_Read`.
#[derive(Clone, Debug)]
pub struct PcrReadResult {
    /// The PCR update counter at read time.
    pub update_counter: u32,
    /// The banks/PCRs the TPM actually read back.
    pub selection: crate::types::structures::PcrSelectionList,
    /// The digest values, positionally matching `selection`.
    pub values: alloc::vec::Vec<Buffer>,
}
