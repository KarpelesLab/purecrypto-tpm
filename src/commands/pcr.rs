//! PCR commands: read banks and extend a PCR.

use alloc::vec::Vec;

use crate::commands::PcrReadResult;
use crate::error::Result;
use crate::marshal::{Marshal, Reader};
use crate::session::permanent_name;
use crate::tpm::{Auth, Tpm};
use crate::transport::Transport;
use crate::types::constants::{Alg, cc};
use crate::types::handles::Handle;
use crate::types::structures::{Buffer, PcrSelection, PcrSelectionList, read_digest_list};

impl<T: Transport> Tpm<T> {
    /// `TPM2_PCR_Read` — read the PCRs named by `selection`.
    pub fn pcr_read(&mut self, selection: &PcrSelectionList) -> Result<PcrReadResult> {
        let mut p = Vec::new();
        selection.marshal(&mut p);
        let resp = self.run(cc::PCR_READ, &[], &[], &p, &mut Auth::None, 0)?;
        let mut r = Reader::new(&resp.params);
        let update_counter = r.u32()?;
        let selection = PcrSelectionList::unmarshal_from(&mut r)?;
        let values = read_digest_list(&mut r)?;
        Ok(PcrReadResult {
            update_counter,
            selection,
            values,
        })
    }

    /// Convenience: read one PCR from one bank, returning its digest (or
    /// `None` if the TPM read back no value, e.g. an unallocated bank).
    pub fn pcr_read_one(&mut self, bank: Alg, pcr: u8) -> Result<Option<Buffer>> {
        let sel = PcrSelectionList(alloc::vec![PcrSelection::single(bank, pcr)]);
        let res = self.pcr_read(&sel)?;
        Ok(res.values.into_iter().next())
    }

    /// `TPM2_PCR_Extend` — extend `pcr` with one digest per bank in `digests`
    /// (`(bankAlg, digest)` pairs; each digest must be the bank hash's size).
    ///
    /// The PCR's auth is usually empty; pass `Auth::Password(b"")` for that.
    pub fn pcr_extend(
        &mut self,
        pcr: u32,
        digests: &[(Alg, &[u8])],
        auth: &mut Auth<'_>,
    ) -> Result<()> {
        let handle = Handle(pcr);
        // TPML_DIGEST_VALUES: count, then each TPMT_HA (alg || fixed digest).
        let mut p = Vec::new();
        (digests.len() as u32).marshal(&mut p);
        for (alg, dig) in digests {
            alg.marshal(&mut p);
            p.extend_from_slice(dig);
        }
        let name = permanent_name(handle);
        self.run(cc::PCR_EXTEND, &[handle], &[&name], &p, auth, 0)?;
        Ok(())
    }
}

impl PcrSelectionList {
    /// Parses a `TPML_PCR_SELECTION` from `r`. (Inherent shim so command code
    /// can call it without importing the [`Unmarshal`](crate::marshal::Unmarshal)
    /// trait.)
    fn unmarshal_from(r: &mut Reader<'_>) -> Result<Self> {
        <Self as crate::marshal::Unmarshal>::unmarshal(r)
    }
}
