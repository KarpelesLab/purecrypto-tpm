//! Simulator TCP transport — `swtpm --tpm2` and the Microsoft / IBM
//! *MS Simulator* (`ms-tpm-20-ref`).
//!
//! Both expose a **command/data** socket (default `127.0.0.1:2321`) speaking
//! the same framing: a big-endian `UINT32` selector, then for
//! `TPM_SEND_COMMAND` a `UINT8` locality, a `UINT32` length and the TPM command
//! bytes; the reply is a `UINT32` length, that many response bytes, then a
//! `UINT32` simulator result code. [`transmit`](Transport::transmit) speaks
//! exactly this, so it works against **both** simulators.
//!
//! They differ on **initialization**:
//!
//! * **swtpm** — its control socket (2322) is *not* mssim-compatible (it uses
//!   swtpm's own ioctl protocol), so we don't touch it. Instead launch swtpm
//!   with `--flags not-need-init,startup-clear` so the TPM powers on and runs
//!   `TPM2_Startup(CLEAR)` itself; then just [`connect`](Self::connect) the
//!   data socket. This is the recommended path.
//! * **ms-tpm-20-ref / IBM** — power, NV and reset are *platform signals* sent
//!   to a second socket (2322) using the same framing as the data socket. Use
//!   [`connect_mssim`](Self::connect_mssim) to attach both, then
//!   [`power_on`](Self::power_on) before `TPM2_Startup`.

use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use crate::error::{Error, Result};
use crate::transport::Transport;

const TPM_SIGNAL_POWER_ON: u32 = 1;
const TPM_SIGNAL_NV_ON: u32 = 11;
const TPM_SEND_COMMAND: u32 = 8;
const TPM_SESSION_END: u32 = 20;

/// The default simulator command/data port.
pub const DEFAULT_ADDR: &str = "127.0.0.1:2321";

/// The default platform/control port (`ms-tpm-20-ref` only).
pub const DEFAULT_PLATFORM_ADDR: &str = "127.0.0.1:2322";

/// Refuse an absurd declared response length from a hostile/confused peer
/// rather than allocating unboundedly.
const MAX_RESPONSE: usize = 1 << 20;

/// A TPM reached through the mssim TCP data protocol.
pub struct SimulatorTransport {
    cmd: TcpStream,
    /// Platform socket for mssim power/NV signals; absent for swtpm.
    platform: Option<TcpStream>,
    locality: u8,
}

impl SimulatorTransport {
    /// Connects the data socket at [`DEFAULT_ADDR`]. Use this with a swtpm
    /// started with `--flags startup-clear` (the TPM is already powered and
    /// started).
    pub fn connect_default() -> Result<Self> {
        Self::connect(DEFAULT_ADDR)
    }

    /// Connects only the data socket. Suitable for swtpm (`startup-clear`) or
    /// for an already-powered ms-tpm-20-ref. [`power_on`](Self::power_on) is
    /// unavailable until a platform socket is attached.
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Self> {
        let cmd =
            TcpStream::connect(addr).map_err(|e| Error::Transport(format!("connect: {e}")))?;
        cmd.set_nodelay(true).ok();
        Ok(SimulatorTransport {
            cmd,
            platform: None,
            locality: 0,
        })
    }

    /// Connects both sockets at [`DEFAULT_ADDR`] / [`DEFAULT_PLATFORM_ADDR`]
    /// for the ms-tpm-20-ref / IBM simulator. Follow with
    /// [`power_on`](Self::power_on) then `TPM2_Startup`.
    pub fn connect_mssim_default() -> Result<Self> {
        Self::connect_mssim(DEFAULT_ADDR, DEFAULT_PLATFORM_ADDR)
    }

    /// Connects both the data socket and the mssim platform socket, for the
    /// ms-tpm-20-ref / IBM simulator. Follow with [`power_on`](Self::power_on)
    /// then `TPM2_Startup`.
    pub fn connect_mssim(
        cmd_addr: impl ToSocketAddrs,
        platform_addr: impl ToSocketAddrs,
    ) -> Result<Self> {
        let mut t = Self::connect(cmd_addr)?;
        let platform = TcpStream::connect(platform_addr)
            .map_err(|e| Error::Transport(format!("connect platform: {e}")))?;
        platform.set_nodelay(true).ok();
        t.platform = Some(platform);
        Ok(t)
    }

    /// Sets the locality byte sent with each command (default 0).
    pub fn set_locality(&mut self, locality: u8) {
        self.locality = locality;
    }

    /// Powers the simulated TPM on and enables NV storage, over the **platform
    /// socket** (ms-tpm-20-ref / IBM only). Returns [`Error::Usage`] if no
    /// platform socket was attached (e.g. for swtpm, which auto-powers via
    /// `--flags startup-clear`).
    pub fn power_on(&mut self) -> Result<()> {
        self.platform_signal(TPM_SIGNAL_POWER_ON)?;
        self.platform_signal(TPM_SIGNAL_NV_ON)?;
        Ok(())
    }

    /// Sends the orderly `TPM_SESSION_END` framing code on the data socket so
    /// the simulator can release the connection cleanly. Best-effort.
    pub fn session_end(&mut self) -> Result<()> {
        write_u32(&mut self.cmd, TPM_SESSION_END)
    }

    fn platform_signal(&mut self, code: u32) -> Result<()> {
        let platform = self.platform.as_mut().ok_or(Error::Usage(
            "no platform socket; connect with connect_mssim (swtpm uses --flags startup-clear instead)",
        ))?;
        write_u32(platform, code)?;
        let rc = read_u32(platform)?;
        if rc != 0 {
            return Err(Error::Transport(format!(
                "simulator platform signal {code} failed: rc={rc}"
            )));
        }
        Ok(())
    }
}

impl Transport for SimulatorTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        // TPM_SEND_COMMAND || locality || UINT32 len || command bytes.
        write_u32(&mut self.cmd, TPM_SEND_COMMAND)?;
        self.cmd
            .write_all(&[self.locality])
            .map_err(|e| Error::Transport(e.to_string()))?;
        write_u32(&mut self.cmd, command.len() as u32)?;
        self.cmd
            .write_all(command)
            .map_err(|e| Error::Transport(format!("write command: {e}")))?;
        self.cmd
            .flush()
            .map_err(|e| Error::Transport(e.to_string()))?;

        // UINT32 response length || response bytes || UINT32 result code.
        let len = read_u32(&mut self.cmd)? as usize;
        if len > MAX_RESPONSE {
            return Err(Error::Transport(format!(
                "simulator response too large: {len} bytes"
            )));
        }
        let mut resp = vec![0u8; len];
        self.cmd
            .read_exact(&mut resp)
            .map_err(|e| Error::Transport(format!("read response: {e}")))?;
        let rc = read_u32(&mut self.cmd)?;
        if rc != 0 {
            return Err(Error::Transport(format!("simulator send failed: rc={rc}")));
        }
        Ok(resp)
    }
}

fn write_u32(s: &mut TcpStream, v: u32) -> Result<()> {
    s.write_all(&v.to_be_bytes())
        .map_err(|e| Error::Transport(e.to_string()))
}

fn read_u32(s: &mut TcpStream) -> Result<u32> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b)
        .map_err(|e| Error::Transport(e.to_string()))?;
    Ok(u32::from_be_bytes(b))
}
