//! Microsoft *MS Simulator* TCP transport (`ms-tpm-20-ref`, `swtpm --tpm2`).
//!
//! The simulator exposes a tiny framing protocol on a TCP socket (default
//! `127.0.0.1:2321`). Each interaction is a big-endian `UINT32` command
//! selector followed by command-specific data:
//!
//! * **`TPM_SEND_COMMAND` (8)** — `UINT8` locality, `UINT32` length, the TPM
//!   command bytes. The reply is a `UINT32` length, that many response bytes,
//!   then a `UINT32` simulator result code (0 on success).
//! * **Power/NV signals** (`TPM_SIGNAL_POWER_ON` (1), `TPM_SIGNAL_NV_ON`
//!   (11), …) — no payload; the reply is just a `UINT32` result code.
//!
//! A fresh simulator must be powered on and have NV enabled before it accepts
//! `TPM2_Startup`; [`power_on`](SimulatorTransport::power_on) does both.

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

/// The default simulator command port.
pub const DEFAULT_ADDR: &str = "127.0.0.1:2321";

/// Bound matching [`device::MAX_RESPONSE`](super::device) — the simulator
/// declares its own length, but we refuse an absurd one rather than allocate
/// unboundedly from a hostile peer.
const MAX_RESPONSE: usize = 1 << 20;

/// A TPM accessed through the MS-simulator TCP protocol.
pub struct SimulatorTransport {
    stream: TcpStream,
    locality: u8,
}

impl SimulatorTransport {
    /// Connects to the simulator at [`DEFAULT_ADDR`].
    pub fn connect_default() -> Result<Self> {
        Self::connect(DEFAULT_ADDR)
    }

    /// Connects to a simulator command port.
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).map_err(|e| Error::Transport(format!("connect: {e}")))?;
        stream.set_nodelay(true).ok();
        Ok(SimulatorTransport {
            stream,
            locality: 0,
        })
    }

    /// Sets the locality byte sent with each command (default 0).
    pub fn set_locality(&mut self, locality: u8) {
        self.locality = locality;
    }

    /// Powers the simulated TPM on and enables NV storage. Run this once after
    /// connecting to a freshly-started simulator, before `TPM2_Startup`.
    pub fn power_on(&mut self) -> Result<()> {
        self.signal(TPM_SIGNAL_POWER_ON)?;
        self.signal(TPM_SIGNAL_NV_ON)?;
        Ok(())
    }

    /// Sends the orderly `TPM_SESSION_END` framing byte-code, letting the
    /// simulator release the connection cleanly. Best-effort.
    pub fn session_end(&mut self) -> Result<()> {
        self.write_u32(TPM_SESSION_END)
    }

    fn signal(&mut self, code: u32) -> Result<()> {
        self.write_u32(code)?;
        let rc = self.read_u32()?;
        if rc != 0 {
            return Err(Error::Transport(format!(
                "simulator signal {code} failed: rc={rc}"
            )));
        }
        Ok(())
    }

    fn write_u32(&mut self, v: u32) -> Result<()> {
        self.stream
            .write_all(&v.to_be_bytes())
            .map_err(|e| Error::Transport(e.to_string()))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut b = [0u8; 4];
        self.stream
            .read_exact(&mut b)
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(u32::from_be_bytes(b))
    }
}

impl Transport for SimulatorTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        // TPM_SEND_COMMAND || locality || UINT32 len || command bytes.
        self.write_u32(TPM_SEND_COMMAND)?;
        self.stream
            .write_all(&[self.locality])
            .map_err(|e| Error::Transport(e.to_string()))?;
        self.write_u32(command.len() as u32)?;
        self.stream
            .write_all(command)
            .map_err(|e| Error::Transport(format!("write command: {e}")))?;
        self.stream
            .flush()
            .map_err(|e| Error::Transport(e.to_string()))?;

        // UINT32 response length || response bytes || UINT32 result code.
        let len = self.read_u32()? as usize;
        if len > MAX_RESPONSE {
            return Err(Error::Transport(format!(
                "simulator response too large: {len} bytes"
            )));
        }
        let mut resp = vec![0u8; len];
        self.stream
            .read_exact(&mut resp)
            .map_err(|e| Error::Transport(format!("read response: {e}")))?;
        let rc = self.read_u32()?;
        if rc != 0 {
            return Err(Error::Transport(format!("simulator send failed: rc={rc}")));
        }
        Ok(resp)
    }
}
