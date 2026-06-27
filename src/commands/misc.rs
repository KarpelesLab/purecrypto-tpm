//! Startup, randomness and capability commands — all unauthenticated
//! (`TPM_ST_NO_SESSIONS`).

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::marshal::Marshal;
use crate::tpm::{Auth, Tpm};
use crate::transport::Transport;
use crate::types::constants::cc;

/// Raw `TPM2_GetCapability` reply: whether more data is available and the
/// undecoded `capabilityData` bytes (a `TPMU_CAPABILITIES`, which callers parse
/// per the capability requested).
#[derive(Clone, Debug)]
pub struct CapabilityData {
    /// `true` if the TPM has more entries than it returned.
    pub more: bool,
    /// The capability code echoed at the head of `capabilityData`.
    pub capability: u32,
    /// The remaining `capabilityData` bytes after the capability code.
    pub data: Vec<u8>,
}

impl<T: Transport> Tpm<T> {
    /// `TPM2_Startup` — initialise the TPM. `startup_type` is
    /// [`su::CLEAR`](crate::types::constants::su::CLEAR) or
    /// [`su::STATE`](crate::types::constants::su::STATE).
    pub fn startup(&mut self, startup_type: u16) -> Result<()> {
        let mut p = Vec::new();
        startup_type.marshal(&mut p);
        self.run(cc::STARTUP, &[], &[], &p, &mut Auth::None, 0)?;
        Ok(())
    }

    /// `TPM2_Shutdown` — prepare for power loss, saving state per
    /// `shutdown_type`.
    pub fn shutdown(&mut self, shutdown_type: u16) -> Result<()> {
        let mut p = Vec::new();
        shutdown_type.marshal(&mut p);
        self.run(cc::SHUTDOWN, &[], &[], &p, &mut Auth::None, 0)?;
        Ok(())
    }

    /// `TPM2_SelfTest` — run self-tests. `full` requests a complete retest
    /// rather than only the not-yet-tested algorithms.
    pub fn self_test(&mut self, full: bool) -> Result<()> {
        let p = [full as u8];
        self.run(cc::SELF_TEST, &[], &[], &p, &mut Auth::None, 0)?;
        Ok(())
    }

    /// `TPM2_GetRandom` — request up to `bytes` random bytes. The TPM may
    /// return fewer; this returns exactly what it gave.
    pub fn get_random(&mut self, bytes: u16) -> Result<Vec<u8>> {
        let mut p = Vec::new();
        bytes.marshal(&mut p);
        let resp = self.run(cc::GET_RANDOM, &[], &[], &p, &mut Auth::None, 0)?;
        let mut r = crate::marshal::Reader::new(&resp.params);
        Ok(r.tpm2b()?.to_vec())
    }

    /// `TPM2_StirRandom` — mix `data` into the TPM's entropy pool.
    pub fn stir_random(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > 128 {
            return Err(Error::Usage("StirRandom accepts at most 128 bytes"));
        }
        let mut p = Vec::new();
        crate::marshal::marshal_tpm2b(data, &mut p)?;
        self.run(cc::STIR_RANDOM, &[], &[], &p, &mut Auth::None, 0)?;
        Ok(())
    }

    /// `TPM2_GetCapability` — query a capability group, returning the raw
    /// `capabilityData` for the caller to interpret.
    ///
    /// `capability` is a [`cap`](crate::types::constants::cap) code, `property`
    /// the first item to return, `count` the maximum number of items.
    pub fn get_capability(
        &mut self,
        capability: u32,
        property: u32,
        count: u32,
    ) -> Result<CapabilityData> {
        let mut p = Vec::new();
        capability.marshal(&mut p);
        property.marshal(&mut p);
        count.marshal(&mut p);
        let resp = self.run(cc::GET_CAPABILITY, &[], &[], &p, &mut Auth::None, 0)?;
        let mut r = crate::marshal::Reader::new(&resp.params);
        let more = r.u8()? != 0;
        let cap = r.u32()?;
        let data = r.take(r.remaining())?.to_vec();
        Ok(CapabilityData {
            more,
            capability: cap,
            data,
        })
    }
}
