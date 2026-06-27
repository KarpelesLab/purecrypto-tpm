//! TPM 2.0 constant code points (TPM 2.0 Library, Part 2, §6).
//!
//! These are grouped into modules by their specification namespace — `cc`
//! (`TPM_CC` command codes), `st` (`TPM_ST` structure tags), `su`
//! (`TPM_SU` startup types), `se` (`TPM_SE` session types), `cap`
//! (`TPM_CAP` capability groups), and `pt` (`TPM_PT` properties) — plus the
//! [`Alg`] algorithm-id newtype and the [`rh`] reserved-handle constants.

/// `TPM_ST` — structure (command/response) tags.
pub mod st {
    /// A command/response carrying no authorization sessions.
    pub const NO_SESSIONS: u16 = 0x8001;
    /// A command/response whose handle area is followed by an authorization
    /// (session) area.
    pub const SESSIONS: u16 = 0x8002;
    /// `TPM_ST_HASHCHECK` — a ticket type (used by some signing flows).
    pub const HASHCHECK: u16 = 0x8024;
    /// `TPM_ST_CREATION` — a creation ticket.
    pub const CREATION: u16 = 0x8021;
}

/// `TPM_SU` — startup / shutdown types.
pub mod su {
    /// Cold/warm reset: TPM state is reinitialised.
    pub const CLEAR: u16 = 0x0000;
    /// Resume previously-saved state.
    pub const STATE: u16 = 0x0001;
}

/// `TPM_SE` — session types, as passed to `TPM2_StartAuthSession`.
pub mod se {
    /// An HMAC session.
    pub const HMAC: u8 = 0x00;
    /// A policy session.
    pub const POLICY: u8 = 0x01;
    /// A trial policy session (computes a policy digest without enforcing it).
    pub const TRIAL: u8 = 0x03;
}

/// `TPM_CC` — command codes (Part 2, §6.5).
pub mod cc {
    /// `TPM2_Startup`.
    pub const STARTUP: u32 = 0x0000_0144;
    /// `TPM2_Shutdown`.
    pub const SHUTDOWN: u32 = 0x0000_0145;
    /// `TPM2_SelfTest`.
    pub const SELF_TEST: u32 = 0x0000_0143;
    /// `TPM2_GetCapability`.
    pub const GET_CAPABILITY: u32 = 0x0000_017A;
    /// `TPM2_GetRandom`.
    pub const GET_RANDOM: u32 = 0x0000_017B;
    /// `TPM2_StirRandom`.
    pub const STIR_RANDOM: u32 = 0x0000_0146;
    /// `TPM2_PCR_Read`.
    pub const PCR_READ: u32 = 0x0000_017E;
    /// `TPM2_PCR_Extend`.
    pub const PCR_EXTEND: u32 = 0x0000_0182;
    /// `TPM2_StartAuthSession`.
    pub const START_AUTH_SESSION: u32 = 0x0000_0176;
    /// `TPM2_CreatePrimary`.
    pub const CREATE_PRIMARY: u32 = 0x0000_0131;
    /// `TPM2_Create`.
    pub const CREATE: u32 = 0x0000_0153;
    /// `TPM2_Load`.
    pub const LOAD: u32 = 0x0000_0157;
    /// `TPM2_Unseal`.
    pub const UNSEAL: u32 = 0x0000_015E;
    /// `TPM2_FlushContext`.
    pub const FLUSH_CONTEXT: u32 = 0x0000_0165;
}

/// `TPM_CAP` — capability groups for `TPM2_GetCapability`.
pub mod cap {
    /// `TPM_CAP_ALGS`.
    pub const ALGS: u32 = 0x0000_0000;
    /// `TPM_CAP_HANDLES`.
    pub const HANDLES: u32 = 0x0000_0001;
    /// `TPM_CAP_COMMANDS`.
    pub const COMMANDS: u32 = 0x0000_0002;
    /// `TPM_CAP_PCRS`.
    pub const PCRS: u32 = 0x0000_0005;
    /// `TPM_CAP_TPM_PROPERTIES`.
    pub const TPM_PROPERTIES: u32 = 0x0000_0006;
}

/// `TPM_PT` — a selection of fixed/variable properties (Part 2, §6.13).
pub mod pt {
    /// Base for the "fixed" property group.
    pub const FIXED: u32 = 0x0000_0100;
    /// Manufacturer id (`TPM_PT_MANUFACTURER`).
    pub const MANUFACTURER: u32 = FIXED + 5;
    /// First of the four `TPM_PT_VENDOR_STRING_*` properties.
    pub const VENDOR_STRING_1: u32 = FIXED + 6;
    /// Firmware version, high word (`TPM_PT_FIRMWARE_VERSION_1`).
    pub const FIRMWARE_VERSION_1: u32 = FIXED + 11;
}

/// Reserved handles (`TPM_RH_*`) and the password-authorization pseudo-session.
pub mod rh {
    /// `TPM_RH_OWNER` — the storage (owner) hierarchy.
    pub const OWNER: u32 = 0x4000_0001;
    /// `TPM_RH_NULL` — the null hierarchy (ephemeral; keys vanish on reset).
    pub const NULL: u32 = 0x4000_0007;
    /// `TPM_RH_LOCKOUT` — the dictionary-attack lockout authority.
    pub const LOCKOUT: u32 = 0x4000_000A;
    /// `TPM_RH_ENDORSEMENT` — the endorsement (privacy) hierarchy.
    pub const ENDORSEMENT: u32 = 0x4000_000B;
    /// `TPM_RH_PLATFORM` — the platform hierarchy.
    pub const PLATFORM: u32 = 0x4000_000C;
    /// `TPM_RS_PW` — the password authorization "session" (no HMAC).
    pub const PW: u32 = 0x4000_0009;
}

use crate::error::Result;
use crate::marshal::{Marshal, Reader, Unmarshal};
use alloc::vec::Vec;

/// `TPM_ALG_ID` — a 16-bit algorithm identifier (Part 2, §6.3).
///
/// A thin newtype over the wire value with named constants for the algorithms
/// this crate handles, plus [`digest_size`](Alg::digest_size) for the hash
/// algorithms (the one piece of per-algorithm knowledge the session layer
/// needs).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Alg(pub u16);

#[allow(missing_docs)]
impl Alg {
    pub const ERROR: Alg = Alg(0x0000);
    pub const RSA: Alg = Alg(0x0001);
    pub const SHA1: Alg = Alg(0x0004);
    pub const HMAC: Alg = Alg(0x0005);
    pub const AES: Alg = Alg(0x0006);
    pub const KEYEDHASH: Alg = Alg(0x0008);
    pub const XOR: Alg = Alg(0x000A);
    pub const SHA256: Alg = Alg(0x000B);
    pub const SHA384: Alg = Alg(0x000C);
    pub const SHA512: Alg = Alg(0x000D);
    pub const NULL: Alg = Alg(0x0010);
    pub const SM3_256: Alg = Alg(0x0012);
    pub const ECDSA: Alg = Alg(0x0018);
    pub const ECDH: Alg = Alg(0x0019);
    pub const RSASSA: Alg = Alg(0x0014);
    pub const RSAES: Alg = Alg(0x0015);
    pub const RSAPSS: Alg = Alg(0x0016);
    pub const OAEP: Alg = Alg(0x0017);
    pub const ECC: Alg = Alg(0x0023);
    pub const SYMCIPHER: Alg = Alg(0x0025);
    pub const CFB: Alg = Alg(0x0043);

    /// The raw 16-bit value.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// The output size in bytes of a hash algorithm, or `None` for any
    /// non-hash (or unknown) algorithm. `TPM_ALG_NULL` maps to `Some(0)`.
    pub const fn digest_size(self) -> Option<usize> {
        match self.0 {
            x if x == Self::SHA1.0 => Some(20),
            x if x == Self::SHA256.0 => Some(32),
            x if x == Self::SHA384.0 => Some(48),
            x if x == Self::SHA512.0 => Some(64),
            x if x == Self::SM3_256.0 => Some(32),
            x if x == Self::NULL.0 => Some(0),
            _ => None,
        }
    }
}

impl core::fmt::Debug for Alg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Alg(0x{:04x})", self.0)
    }
}

impl Marshal for Alg {
    #[inline]
    fn marshal(&self, out: &mut Vec<u8>) {
        self.0.marshal(out);
    }
}

impl Unmarshal for Alg {
    #[inline]
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Alg(r.u16()?))
    }
}
