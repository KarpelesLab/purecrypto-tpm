//! Moving command bytes to a TPM and reading the response back.
//!
//! [`Transport`] is the one operation the command layer needs: hand it a fully
//! marshalled command (header included) and get the full response back. It is
//! deliberately synchronous and byte-in/byte-out so the rest of the crate is
//! transport-agnostic and `no_std`-friendly.
//!
//! Two `std` backends ship:
//!
//! * [`DeviceTransport`] — a Linux TPM character device (`/dev/tpmrm0`, the
//!   in-kernel resource manager, or the raw `/dev/tpm0`).
//! * [`SimulatorTransport`] — the Microsoft *MS Simulator* (`ms-tpm-20-ref`,
//!   also spoken by `swtpm --tpm2`) TCP protocol, for testing without
//!   hardware or root.

use alloc::vec::Vec;

use crate::error::Result;

/// A channel that carries one TPM command and returns its one response.
pub trait Transport {
    /// Sends a complete, marshalled TPM command and returns the complete
    /// response bytes (header included). Implementations must deliver exactly
    /// one command and read back exactly one response.
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}

/// `Transport` is implemented for `&mut T` so a borrowed transport can be used
/// without giving up ownership.
impl<T: Transport + ?Sized> Transport for &mut T {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        (**self).transmit(command)
    }
}

#[cfg(feature = "device")]
mod device;
#[cfg(feature = "device")]
pub use device::DeviceTransport;

#[cfg(feature = "simulator")]
mod simulator;
#[cfg(feature = "simulator")]
pub use simulator::SimulatorTransport;
