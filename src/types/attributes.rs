//! Attribute bit-fields: `TPMA_OBJECT` and `TPMA_SESSION` (Part 2, §8).
//!
//! Both are plain integers on the wire (`UINT32` and `UINT8` respectively); we
//! wrap them so the named bits and the common combinations are discoverable
//! and so a builder style reads clearly at the call site.

use alloc::vec::Vec;

use crate::error::Result;
use crate::marshal::{Marshal, Reader, Unmarshal};

/// `TPMA_OBJECT` — the attributes of a loaded/created object (a `UINT32`).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct ObjectAttributes(pub u32);

#[allow(missing_docs)]
impl ObjectAttributes {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const ST_CLEAR: u32 = 1 << 2;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
    pub const NO_DA: u32 = 1 << 10;
    pub const ENCRYPTED_DUPLICATION: u32 = 1 << 11;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN_ENCRYPT: u32 = 1 << 18;

    /// An empty attribute set.
    pub const fn empty() -> Self {
        ObjectAttributes(0)
    }

    /// Whether all bits in `bits` are set.
    pub const fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }

    /// Returns a copy with `bits` set.
    pub const fn with(self, bits: u32) -> Self {
        ObjectAttributes(self.0 | bits)
    }

    /// The attribute set of a typical **restricted storage parent** (a primary
    /// or ordinary storage key): a non-duplicable, TPM-resident decryption key
    /// whose sensitive half the TPM generates and that is authorised by its
    /// auth value. This is the parent under which sealed blobs and child keys
    /// live.
    pub const fn storage_parent() -> Self {
        ObjectAttributes(
            Self::FIXED_TPM
                | Self::FIXED_PARENT
                | Self::SENSITIVE_DATA_ORIGIN
                | Self::USER_WITH_AUTH
                | Self::RESTRICTED
                | Self::DECRYPT,
        )
    }

    /// The attribute set of a **sealed data object** (a `keyedhash` with no
    /// scheme): non-duplicable, auth-value protected, with externally-supplied
    /// sensitive data (so *not* `sensitiveDataOrigin`). Neither `sign` nor
    /// `decrypt` — sealed data is only ever unsealed.
    pub const fn sealed_data() -> Self {
        ObjectAttributes(Self::FIXED_TPM | Self::FIXED_PARENT | Self::USER_WITH_AUTH)
    }
}

impl core::fmt::Debug for ObjectAttributes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ObjectAttributes(0x{:08x})", self.0)
    }
}

impl Marshal for ObjectAttributes {
    #[inline]
    fn marshal(&self, out: &mut Vec<u8>) {
        self.0.marshal(out);
    }
}

impl Unmarshal for ObjectAttributes {
    #[inline]
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ObjectAttributes(r.u32()?))
    }
}

/// `TPMA_SESSION` — the attributes of an authorization session (a `UINT8`),
/// as carried in each session of a command/response authorization area.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionAttributes(pub u8);

#[allow(missing_docs)]
impl SessionAttributes {
    /// Keep the session loaded after the command (otherwise it is flushed).
    pub const CONTINUE_SESSION: u8 = 1 << 0;
    pub const AUDIT_EXCLUSIVE: u8 = 1 << 1;
    pub const AUDIT_RESET: u8 = 1 << 2;
    /// The session encrypts the first command parameter (`decrypt` from the
    /// TPM's perspective: it decrypts what it receives).
    pub const DECRYPT: u8 = 1 << 5;
    /// The session encrypts the first response parameter.
    pub const ENCRYPT: u8 = 1 << 6;
    pub const AUDIT: u8 = 1 << 7;

    /// An empty attribute set.
    pub const fn empty() -> Self {
        SessionAttributes(0)
    }

    /// Just `continueSession` — the usual choice for a session reused across
    /// several commands.
    pub const fn continue_session() -> Self {
        SessionAttributes(Self::CONTINUE_SESSION)
    }

    /// Whether all bits in `bits` are set.
    pub const fn contains(self, bits: u8) -> bool {
        self.0 & bits == bits
    }

    /// Returns a copy with `bits` set.
    pub const fn with(self, bits: u8) -> Self {
        SessionAttributes(self.0 | bits)
    }
}

impl core::fmt::Debug for SessionAttributes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SessionAttributes(0x{:02x})", self.0)
    }
}

impl Marshal for SessionAttributes {
    #[inline]
    fn marshal(&self, out: &mut Vec<u8>) {
        self.0.marshal(out);
    }
}

impl Unmarshal for SessionAttributes {
    #[inline]
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
        Ok(SessionAttributes(r.u8()?))
    }
}
