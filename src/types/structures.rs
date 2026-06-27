//! The TPM structure subset this crate models (Part 2, §10–12).
//!
//! Two design choices keep this small:
//!
//! * **`TPM2B_*` buffers are [`Buffer`]** — a length-prefixed byte vector. A
//!   digest, a private blob, a Name, an auth value and sealed data are all
//!   `Buffer`s; their meaning comes from context, not from distinct types.
//! * **`TPMT_PUBLIC` is marshal-only.** We *build* public-area templates to
//!   send (storage parents, sealed objects), but we never parse a
//!   `TPMT_PUBLIC` back: every command that returns one also returns the
//!   object's Name and a re-loadable `TPM2B_PUBLIC` blob, which we keep
//!   verbatim as a `Buffer`. That avoids a full `TPMU_*` union parser while
//!   staying byte-exact for re-`Load`ing.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::marshal::{Marshal, Reader, Unmarshal, marshal_tpm2b};
use crate::types::attributes::ObjectAttributes;
use crate::types::constants::Alg;

/// `TPM_ECC_CURVE` values we reference.
pub mod ecc_curve {
    /// NIST P-256 (`TPM_ECC_NIST_P256`).
    pub const NIST_P256: u16 = 0x0003;
    /// NIST P-384 (`TPM_ECC_NIST_P384`).
    pub const NIST_P384: u16 = 0x0004;
}

/// A `TPM2B_*` buffer: a `UINT16`-length-prefixed byte string.
///
/// Used for every sized buffer the spec gives a distinct `TPM2B_*` name —
/// digests, auth values, Names, private blobs, sealed data, the opaque
/// `TPM2B_PUBLIC` re-load blob, and so on.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Buffer(pub Vec<u8>);

impl Buffer {
    /// An empty buffer (marshals as the two bytes `00 00`).
    pub fn empty() -> Self {
        Buffer(Vec::new())
    }

    /// Borrows the contained bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the buffer, yielding its bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// The byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(v: Vec<u8>) -> Self {
        Buffer(v)
    }
}

impl From<&[u8]> for Buffer {
    fn from(v: &[u8]) -> Self {
        Buffer(v.to_vec())
    }
}

impl core::fmt::Debug for Buffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Buffer({} bytes)", self.0.len())
    }
}

impl Marshal for Buffer {
    fn marshal(&self, out: &mut Vec<u8>) {
        // A Buffer never exceeds 2^16-1 in practice; if it somehow did, emit a
        // truncated-but-consistent length rather than panic. Callers building
        // oversized buffers are a usage bug caught elsewhere.
        marshal_tpm2b(&self.0, out).ok();
    }
}

impl Unmarshal for Buffer {
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Buffer(r.tpm2b()?.to_vec()))
    }
}

/// `TPMT_SYM_DEF_OBJECT` — the symmetric algorithm of a storage key's child
/// protection (Part 2, §11.1.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymDefObject {
    /// The symmetric algorithm (`TPM_ALG_AES`, or `TPM_ALG_NULL` for none).
    pub algorithm: Alg,
    /// Key size in bits (ignored when `algorithm` is `NULL`).
    pub key_bits: u16,
    /// Block-cipher mode (`TPM_ALG_CFB` for a storage key; ignored when
    /// `algorithm` is `NULL`).
    pub mode: Alg,
}

impl SymDefObject {
    /// AES-128 in CFB mode — the standard child-protection cipher for a
    /// storage parent.
    pub const fn aes128_cfb() -> Self {
        SymDefObject {
            algorithm: Alg::AES,
            key_bits: 128,
            mode: Alg::CFB,
        }
    }

    /// No symmetric algorithm (`TPM_ALG_NULL`).
    pub const fn null() -> Self {
        SymDefObject {
            algorithm: Alg::NULL,
            key_bits: 0,
            mode: Alg::NULL,
        }
    }
}

impl Marshal for SymDefObject {
    fn marshal(&self, out: &mut Vec<u8>) {
        self.algorithm.marshal(out);
        if self.algorithm != Alg::NULL {
            // TPMU_SYM_KEY_BITS / TPMU_SYM_MODE for a non-XOR symmetric object.
            self.key_bits.marshal(out);
            self.mode.marshal(out);
        }
    }
}

/// The algorithm-specific parameters of a `TPMT_PUBLIC` (`TPMU_PUBLIC_PARMS`),
/// modelled only for the object types this crate creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicParms {
    /// `TPMS_KEYEDHASH_PARMS`. `scheme` is `TPM_ALG_NULL` for a sealed data
    /// object (no HMAC/XOR scheme).
    KeyedHash {
        /// The keyed-hash scheme selector; `NULL` for sealed data.
        scheme: Alg,
    },
    /// `TPMS_ECC_PARMS` for a (restricted) ECC storage key. `scheme` and `kdf`
    /// are `NULL`; `symmetric` describes child protection.
    Ecc {
        /// Symmetric child-protection cipher.
        symmetric: SymDefObject,
        /// Key-use scheme (`NULL` for a storage key).
        scheme: Alg,
        /// `TPM_ECC_CURVE` (see [`ecc_curve`]).
        curve: u16,
        /// KDF scheme (`NULL`).
        kdf: Alg,
    },
}

impl Marshal for PublicParms {
    fn marshal(&self, out: &mut Vec<u8>) {
        match self {
            PublicParms::KeyedHash { scheme } => {
                // TPMT_KEYEDHASH_SCHEME: just the selector when NULL.
                scheme.marshal(out);
            }
            PublicParms::Ecc {
                symmetric,
                scheme,
                curve,
                kdf,
            } => {
                symmetric.marshal(out);
                // TPMT_ECC_SCHEME / TPMT_KDF_SCHEME: selector only when NULL.
                scheme.marshal(out);
                curve.marshal(out);
                kdf.marshal(out);
            }
        }
    }
}

/// The unique/identity field of a `TPMT_PUBLIC` (`TPMU_PUBLIC_ID`). For a
/// freshly-created object the TPM fills this in, so we send the empty form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicId {
    /// `TPM2B_DIGEST` unique value for a keyed-hash / symmetric object.
    KeyedHash(Buffer),
    /// `TPMS_ECC_POINT` (`x`, `y`) for an ECC key.
    Ecc {
        /// X coordinate.
        x: Buffer,
        /// Y coordinate.
        y: Buffer,
    },
}

impl Marshal for PublicId {
    fn marshal(&self, out: &mut Vec<u8>) {
        match self {
            PublicId::KeyedHash(d) => d.marshal(out),
            PublicId::Ecc { x, y } => {
                x.marshal(out);
                y.marshal(out);
            }
        }
    }
}

/// `TPMT_PUBLIC` — the public area of an object (Part 2, §12.2.4).
///
/// Build-only: see the module note. Use [`Public::wrap_2b`] to emit the
/// `TPM2B_PUBLIC` (size-prefixed) form that commands expect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    /// Object type (`TPM_ALG_KEYEDHASH`, `TPM_ALG_ECC`, …).
    pub type_: Alg,
    /// Name algorithm — the hash that computes this object's Name.
    pub name_alg: Alg,
    /// Object attributes (`TPMA_OBJECT`).
    pub attributes: ObjectAttributes,
    /// Authorization policy digest (`TPM2B_DIGEST`; empty for none).
    pub auth_policy: Buffer,
    /// Algorithm parameters.
    pub parameters: PublicParms,
    /// Unique/identity field (sent empty when creating).
    pub unique: PublicId,
}

impl Marshal for Public {
    fn marshal(&self, out: &mut Vec<u8>) {
        self.type_.marshal(out);
        self.name_alg.marshal(out);
        self.attributes.marshal(out);
        self.auth_policy.marshal(out);
        self.parameters.marshal(out);
        self.unique.marshal(out);
    }
}

impl Public {
    /// Emits the `TPM2B_PUBLIC` form: a `UINT16` size prefix over the marshalled
    /// `TPMT_PUBLIC`.
    pub fn wrap_2b(&self, out: &mut Vec<u8>) {
        let inner = self.to_bytes();
        marshal_tpm2b(&inner, out).ok();
    }

    /// A restricted ECC (P-256) storage-parent template: the standard parent
    /// under which sealed blobs and child keys are created, AES-128-CFB child
    /// protection, authorised by its auth value.
    pub fn ecc_storage_parent(name_alg: Alg) -> Self {
        Public {
            type_: Alg::ECC,
            name_alg,
            attributes: ObjectAttributes::storage_parent(),
            auth_policy: Buffer::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDefObject::aes128_cfb(),
                scheme: Alg::NULL,
                curve: ecc_curve::NIST_P256,
                kdf: Alg::NULL,
            },
            unique: PublicId::Ecc {
                x: Buffer::empty(),
                y: Buffer::empty(),
            },
        }
    }

    /// A sealed-data (`keyedhash`, no scheme) template, authorised by its auth
    /// value. The data to seal is supplied separately via
    /// [`SensitiveCreate`].
    pub fn sealed_data(name_alg: Alg) -> Self {
        Public {
            type_: Alg::KEYEDHASH,
            name_alg,
            attributes: ObjectAttributes::sealed_data(),
            auth_policy: Buffer::empty(),
            parameters: PublicParms::KeyedHash { scheme: Alg::NULL },
            unique: PublicId::KeyedHash(Buffer::empty()),
        }
    }
}

/// `TPMS_SENSITIVE_CREATE` — the caller-supplied secret half at creation: an
/// auth value and (for sealed data) the data to protect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SensitiveCreate {
    /// The object's auth value (`TPM2B_AUTH`).
    pub user_auth: Buffer,
    /// Externally-supplied sensitive data (`TPM2B_SENSITIVE_DATA`); empty for
    /// keys whose secret the TPM generates.
    pub data: Buffer,
}

impl SensitiveCreate {
    /// Emits the `TPM2B_SENSITIVE_CREATE` form: a `UINT16` size prefix over the
    /// marshalled `TPMS_SENSITIVE_CREATE`.
    pub fn wrap_2b(&self, out: &mut Vec<u8>) {
        let mut inner = Vec::new();
        self.user_auth.marshal(&mut inner);
        self.data.marshal(&mut inner);
        marshal_tpm2b(&inner, out).ok();
    }
}

/// One `TPMS_PCR_SELECTION`: a bank (`hash`) plus a bitmap selecting PCRs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrSelection {
    /// The PCR bank's hash algorithm.
    pub hash: Alg,
    /// The selection bitmap; PCR *n* is bit `n & 7` of byte `n >> 3`.
    pub select: Vec<u8>,
}

impl PcrSelection {
    /// Builds a selection over a single PCR index in the given bank.
    pub fn single(hash: Alg, pcr: u8) -> Self {
        let byte = (pcr / 8) as usize;
        let mut select = alloc::vec![0u8; byte + 1];
        select[byte] = 1 << (pcr % 8);
        // The TPM expects at least the standard 3-byte (24-PCR) map shape.
        if select.len() < 3 {
            select.resize(3, 0);
        }
        PcrSelection { hash, select }
    }
}

impl Marshal for PcrSelection {
    fn marshal(&self, out: &mut Vec<u8>) {
        self.hash.marshal(out);
        (self.select.len() as u8).marshal(out);
        out.extend_from_slice(&self.select);
    }
}

impl Unmarshal for PcrSelection {
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        let hash = Alg::unmarshal(r)?;
        let size = r.u8()? as usize;
        let select = r.take(size)?.to_vec();
        Ok(PcrSelection { hash, select })
    }
}

/// `TPML_PCR_SELECTION` — a counted list of [`PcrSelection`]s.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcrSelectionList(pub Vec<PcrSelection>);

impl Marshal for PcrSelectionList {
    fn marshal(&self, out: &mut Vec<u8>) {
        (self.0.len() as u32).marshal(out);
        for s in &self.0 {
            s.marshal(out);
        }
    }
}

impl Unmarshal for PcrSelectionList {
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        let count = r.u32()? as usize;
        let mut v = Vec::with_capacity(count.min(16));
        for _ in 0..count {
            v.push(PcrSelection::unmarshal(r)?);
        }
        Ok(PcrSelectionList(v))
    }
}

/// Reads past a `TPMT_TK_CREATION` (tag `UINT16`, hierarchy handle `UINT32`,
/// digest `TPM2B`) without modelling it — we don't use creation tickets yet.
pub(crate) fn skip_tk_creation(r: &mut Reader<'_>) -> Result<()> {
    let _tag = r.u16()?;
    let _hierarchy = r.u32()?;
    let _digest = r.tpm2b()?;
    Ok(())
}

/// Reads a counted (`UINT32`) list of `TPM2B` digests, as in a `PCR_Read`
/// response's `pcrValues`.
pub(crate) fn read_digest_list(r: &mut Reader<'_>) -> Result<Vec<Buffer>> {
    let count = r.u32()? as usize;
    if count > 0xFFFF {
        return Err(Error::Malformed("absurd digest-list count"));
    }
    let mut v = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        v.push(Buffer(r.tpm2b()?.to_vec()));
    }
    Ok(v)
}
