//! Linux TPM character-device transport.
//!
//! The kernel TPM driver is message-oriented: one `write()` submits a command
//! and the following `read()` returns the whole response in a single call.
//! Prefer `/dev/tpmrm0` (the in-kernel *resource manager*, which virtualises
//! handles and contexts) over the raw `/dev/tpm0` unless you have a reason to
//! drive the chip directly.

use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::transport::Transport;

/// The largest response the kernel will hand back in one read. The TPM I/O
/// buffer is bounded (`TPM_PT_MAX_RESPONSE_SIZE`, typically ≤ 4096); we size a
/// little above that so a maximal response always fits.
const MAX_RESPONSE: usize = 4096;

/// A TPM accessed through a Linux character device.
pub struct DeviceTransport {
    file: File,
}

impl DeviceTransport {
    /// Opens `/dev/tpmrm0`, the resource-managed device — the right default
    /// for application use.
    pub fn open_default() -> Result<Self> {
        Self::open("/dev/tpmrm0")
    }

    /// Opens `/dev/tpm0`, the raw device. There is at most one client at a
    /// time and no handle virtualisation; usually you want
    /// [`open_default`](Self::open_default) instead.
    pub fn open_raw() -> Result<Self> {
        Self::open("/dev/tpm0")
    }

    /// Opens a specific TPM character device path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::Transport(format!("open {}: {e}", path.display())))?;
        Ok(DeviceTransport { file })
    }
}

impl Transport for DeviceTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.file
            .write_all(command)
            .map_err(|e| Error::Transport(format!("write command: {e}")))?;
        self.file
            .flush()
            .map_err(|e| Error::Transport(e.to_string()))?;

        let mut buf = vec![0u8; MAX_RESPONSE];
        let n = self
            .file
            .read(&mut buf)
            .map_err(|e| Error::Transport(format!("read response: {e}")))?;
        if n == 0 {
            return Err(Error::Transport("empty TPM response".to_string()));
        }
        buf.truncate(n);
        Ok(buf)
    }
}
