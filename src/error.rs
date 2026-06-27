//! Error and result types.
//!
//! Two failure domains meet here: errors *the TPM reports* — a 32-bit
//! [`TpmRc`] response code carried in every response header — and errors *the
//! host stack raises* (transport I/O, a malformed response, a misuse of the
//! API). [`Error`] unifies them.

use alloc::string::String;
use core::fmt;

/// The crate result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// A TPM 2.0 response code (`TPM_RC`), as carried in the response header.
///
/// The encoding (TPM 2.0 Library, Part 2, §6.6) is layered. `0x000` is
/// success. The "format-zero" space holds version-1.2-compatible codes,
/// warnings (`RC_WARN`) and vendor codes; the "format-one" space (bit 7 set)
/// attaches a *parameter*, *handle* or *session* number to the code so a
/// caller can tell which argument the TPM rejected. [`Self::base`] strips that
/// number back to the canonical code so it can be compared against the `tpm_rc`
/// constants.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TpmRc(pub u32);

impl TpmRc {
    /// `TPM_RC_SUCCESS`.
    pub const SUCCESS: TpmRc = TpmRc(0x000);

    /// The raw 32-bit code.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Whether this code is `TPM_RC_SUCCESS`.
    #[inline]
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// `true` for a "format-one" code (bit 7 set) — one that carries a
    /// parameter/handle/session number.
    #[inline]
    pub const fn is_format_one(self) -> bool {
        self.0 & 0x080 != 0
    }

    /// `true` for an `RC_WARN` warning (format-zero, bit 11 set).
    #[inline]
    pub const fn is_warning(self) -> bool {
        !self.is_format_one() && (self.0 & 0x800 != 0)
    }

    /// The canonical code with any format-one parameter/handle/session number
    /// stripped off. For a format-zero code this is the code itself.
    ///
    /// For a format-one code the low 6 bits plus bit 7 are the code proper
    /// (`0x080..=0x0BF`); bits 8–11 carry the 1-based argument number, which
    /// this masks away.
    pub const fn base(self) -> TpmRc {
        if self.is_format_one() {
            TpmRc(self.0 & 0x0BF)
        } else {
            self
        }
    }

    /// For a format-one code, the 1-based number of the parameter, handle or
    /// session the code refers to, or `None` for a format-zero code.
    ///
    /// Whether the number names a parameter, a handle or a session is told by
    /// bits 6 and 11 (see [`Self::arg_kind`]).
    pub const fn arg_number(self) -> Option<u8> {
        if self.is_format_one() {
            Some(((self.0 >> 8) & 0xF) as u8)
        } else {
            None
        }
    }

    /// For a format-one code, what kind of argument [`Self::arg_number`]
    /// counts.
    pub const fn arg_kind(self) -> Option<ArgKind> {
        if !self.is_format_one() {
            return None;
        }
        // Part 2 §6.6.3: bit 6 set => parameter; otherwise bit 11 set =>
        // session, clear => handle.
        if self.0 & 0x040 != 0 {
            Some(ArgKind::Parameter)
        } else if self.0 & 0x800 != 0 {
            Some(ArgKind::Session)
        } else {
            Some(ArgKind::Handle)
        }
    }
}

impl fmt::Debug for TpmRc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TpmRc(0x{:03x})", self.0)
    }
}

impl fmt::Display for TpmRc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM_RC 0x{:03x}", self.0)?;
        if let (Some(n), Some(kind)) = (self.arg_number(), self.arg_kind()) {
            write!(f, " ({} {})", kind.as_str(), n)?;
        }
        Ok(())
    }
}

/// Which kind of argument a format-one [`TpmRc`] refers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArgKind {
    /// A command handle argument.
    Handle,
    /// A command parameter argument.
    Parameter,
    /// An authorization session.
    Session,
}

impl ArgKind {
    /// A short label for display.
    pub const fn as_str(self) -> &'static str {
        match self {
            ArgKind::Handle => "handle",
            ArgKind::Parameter => "parameter",
            ArgKind::Session => "session",
        }
    }
}

/// Anything that can go wrong talking to a TPM.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The TPM rejected the command with a non-success response code.
    Tpm(TpmRc),
    /// A transport (device / socket) I/O error.
    Transport(String),
    /// A response (or, occasionally, a value we were asked to marshal) was
    /// malformed: truncated, over-long, or structurally invalid.
    Malformed(&'static str),
    /// The TPM's reply did not match the command — e.g. an unexpected tag, a
    /// response whose declared size disagrees with the bytes received, or a
    /// command-specific invariant violated.
    Protocol(String),
    /// The caller used the API incorrectly (e.g. asked for more random bytes
    /// than fit a single command, or supplied an over-long buffer).
    Usage(&'static str),
}

impl Error {
    /// Constructs an [`Error::Tpm`] from a raw response code.
    pub(crate) fn rc(code: u32) -> Self {
        Error::Tpm(TpmRc(code))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tpm(rc) => write!(f, "TPM error: {rc}"),
            Error::Transport(s) => write!(f, "transport error: {s}"),
            Error::Malformed(s) => write!(f, "malformed TPM data: {s}"),
            Error::Protocol(s) => write!(f, "protocol error: {s}"),
            Error::Usage(s) => write!(f, "misuse: {s}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
