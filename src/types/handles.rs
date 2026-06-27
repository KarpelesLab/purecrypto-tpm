//! TPM handles — 32-bit references to objects, sessions, PCRs and reserved
//! authorities (Part 2, §7).
//!
//! The high byte (`TPM_HT`) selects the handle space: `0x00` PCR, `0x02`
//! HMAC/loaded session, `0x03` policy session, `0x40` permanent (`TPM_RH_*`),
//! `0x80` transient object, `0x81` persistent object. We keep a single
//! [`Handle`] newtype rather than one type per space; the helpers here classify
//! a handle when that matters.

use alloc::vec::Vec;

use crate::error::Result;
use crate::marshal::{Marshal, Reader, Unmarshal};

/// A 32-bit TPM handle.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(pub u32);

impl Handle {
    /// The raw 32-bit value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// The handle type (`TPM_HT`), i.e. the high byte.
    #[inline]
    pub const fn handle_type(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// `true` for a transient object handle (`0x80xxxxxx`).
    #[inline]
    pub const fn is_transient(self) -> bool {
        self.handle_type() == 0x80
    }

    /// `true` for a persistent object handle (`0x81xxxxxx`).
    #[inline]
    pub const fn is_persistent(self) -> bool {
        self.handle_type() == 0x81
    }

    /// `true` for a session handle (HMAC `0x02xxxxxx` or policy `0x03xxxxxx`).
    #[inline]
    pub const fn is_session(self) -> bool {
        matches!(self.handle_type(), 0x02 | 0x03)
    }
}

impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Handle(0x{:08x})", self.0)
    }
}

impl From<u32> for Handle {
    #[inline]
    fn from(v: u32) -> Self {
        Handle(v)
    }
}

impl Marshal for Handle {
    #[inline]
    fn marshal(&self, out: &mut Vec<u8>) {
        self.0.marshal(out);
    }
}

impl Unmarshal for Handle {
    #[inline]
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Handle(r.u32()?))
    }
}
