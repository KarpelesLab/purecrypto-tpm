//! TPM 2.0 constants, handles, attributes and structures.
//!
//! The wire-level vocabulary the rest of the crate speaks. Code points live in
//! [`constants`] (with the [`Alg`] algorithm-id newtype), the 32-bit [`Handle`]
//! in [`handles`], the `TPMA_*` bit-fields in [`attributes`], and the modelled
//! `TPM2B_*`/`TPMT_*`/`TPMS_*` structures in [`structures`].
//!
//! The most-used items are re-exported here so callers can write
//! `types::Alg` / `types::Handle` / `types::Public` directly.

pub mod attributes;
pub mod constants;
pub mod handles;
pub mod structures;

pub use attributes::{ObjectAttributes, SessionAttributes};
pub use constants::{Alg, cap, cc, pt, rh, se, st, su};
pub use handles::Handle;
pub use structures::{
    Buffer, PcrSelection, PcrSelectionList, Public, PublicId, PublicParms, SensitiveCreate,
    SymDefObject, ecc_curve,
};
