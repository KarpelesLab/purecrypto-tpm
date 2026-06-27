//! Session lifecycle: start an authorization session, flush a handle.

use alloc::vec::Vec;

use crate::error::Result;
use crate::marshal::{Marshal, Reader, marshal_tpm2b};
use crate::session::Session;
use crate::tpm::{Auth, Tpm};
use crate::transport::Transport;
use crate::types::attributes::SessionAttributes;
use crate::types::constants::{Alg, cc, rh, se};
use crate::types::handles::Handle;
use crate::types::structures::SymDefObject;

impl<T: Transport> Tpm<T> {
    /// `TPM2_StartAuthSession` — start an **unsalted, unbound HMAC session**
    /// over `hash_alg`, with no parameter-encryption cipher.
    ///
    /// `nonce_caller` seeds the rolling-nonce chain and must be at least 16
    /// bytes; under `std` use [`Tpm::start_hmac_session`] to have one generated
    /// for you. The returned [`Session`] carries
    /// [`CONTINUE_SESSION`](SessionAttributes::CONTINUE_SESSION) so it survives
    /// across commands until you [`flush`](Tpm::flush_context) it.
    pub fn start_auth_session(
        &mut self,
        hash_alg: Alg,
        nonce_caller: Vec<u8>,
    ) -> Result<Session> {
        // Handle area: tpmKey (NULL = unsalted), bind (NULL = unbound).
        let handles = [Handle(rh::NULL), Handle(rh::NULL)];

        let mut p = Vec::new();
        marshal_tpm2b(&nonce_caller, &mut p)?; // nonceCaller
        marshal_tpm2b(&[], &mut p)?; // encryptedSalt (none)
        p.push(se::HMAC); // sessionType
        SymDefObject::null().marshal(&mut p); // symmetric = TPM_ALG_NULL
        hash_alg.marshal(&mut p); // authHash

        let resp = self.run(
            cc::START_AUTH_SESSION,
            &handles,
            &[],
            &p,
            &mut Auth::None,
            1,
        )?;
        let session_handle = resp.handles[0];
        let mut r = Reader::new(&resp.params);
        let nonce_tpm = r.tpm2b()?.to_vec();

        Session::new(
            session_handle,
            hash_alg,
            nonce_tpm,
            nonce_caller,
            SessionAttributes::continue_session(),
            b"",
            b"",
            b"",
        )
    }

    /// Like [`start_auth_session`](Tpm::start_auth_session) but draws the
    /// initial `nonceCaller` from the OS CSPRNG.
    #[cfg(feature = "std")]
    pub fn start_hmac_session(&mut self, hash_alg: Alg) -> Result<Session> {
        use purecrypto::rng::{OsRng, RngCore};
        let n = crate::crypto::digest_size(hash_alg)?;
        let mut nonce = alloc::vec![0u8; n];
        OsRng.fill_bytes(&mut nonce);
        self.start_auth_session(hash_alg, nonce)
    }

    /// `TPM2_FlushContext` — evict a transient object or session handle from
    /// TPM memory. `flushHandle` is a parameter, so no authorization is needed.
    pub fn flush_context(&mut self, handle: Handle) -> Result<()> {
        let mut p = Vec::new();
        handle.marshal(&mut p);
        self.run(cc::FLUSH_CONTEXT, &[], &[], &p, &mut Auth::None, 0)?;
        Ok(())
    }
}
