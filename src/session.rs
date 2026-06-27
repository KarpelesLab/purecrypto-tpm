//! Authorization sessions.
//!
//! Every TPM command that touches a protected object carries an *authorization
//! area*. The simplest entry is a **password** (`TPM_RS_PW`): the auth value in
//! the clear, fine over a trusted local bus. An **HMAC session** instead proves
//! knowledge of the auth value without sending it, and binds each use to the
//! exact command via a rolling pair of nonces — defeating replay and, for a
//! salted/bound session, enabling parameter encryption.
//!
//! This module implements both. The HMAC computation follows TPM 2.0 Library
//! Part 1, §19.6:
//!
//! ```text
//! cpHash   = H(commandCode || Names(handles) || parameters)
//! rpHash   = H(responseCode || commandCode  || parameters)
//! authHMAC = HMAC(sessionKey || authValue, pHash || nonceNewer || nonceOlder || attributes)
//! ```
//!
//! with `nonceNewer/nonceOlder` = `nonceCaller/nonceTPM` for a command and the
//! reverse for the response. The `sessionKey` is fixed at session start by
//! KDFa over the bind entity's auth value and the salt (both empty for an
//! unsalted, unbound session, giving an empty `sessionKey`).
//!
//! **Status:** authorization (command HMAC + response HMAC verification) is
//! implemented for unsalted sessions, both unbound and bound. Salted sessions
//! and parameter *encryption* (the CFB transform, for which [`crate::crypto`]
//! already provides the primitive) are not yet wired in.

#[cfg(any(test, feature = "std"))]
use alloc::vec;
use alloc::vec::Vec;

use purecrypto::ct::Choice;

use crate::crypto;
use crate::error::{Error, Result};
use crate::types::attributes::SessionAttributes;
use crate::types::constants::Alg;
use crate::types::handles::Handle;

/// The Name of a permanent/PCR handle (one with no public area) is just the
/// 4-byte handle value. Object handles use the Name returned at load time.
pub fn permanent_name(handle: Handle) -> Vec<u8> {
    handle.raw().to_be_bytes().to_vec()
}

/// One established authorization session.
///
/// Hold onto it across commands (with [`SessionAttributes::CONTINUE_SESSION`])
/// to reuse the rolling-nonce chain; the TPM flushes a session without that
/// attribute after one use.
pub struct Session {
    /// The session handle returned by `TPM2_StartAuthSession`.
    pub handle: Handle,
    /// The session's hash algorithm (`authHash`).
    pub hash_alg: Alg,
    /// The session's attribute bits applied to each command.
    pub attributes: SessionAttributes,
    /// KDFa-derived session key (empty for an unsalted, unbound session).
    session_key: Vec<u8>,
    /// Latest `nonceTPM` (seeded from `StartAuthSession`, updated each reply).
    nonce_tpm: Vec<u8>,
    /// `nonceCaller` sent with the most recent command, kept to verify the
    /// matching response HMAC.
    nonce_caller: Vec<u8>,
    /// Name of the bind entity (empty if the session is unbound). When the
    /// object being authorized *is* the bind entity, its auth value is not
    /// re-appended to the HMAC key.
    bound_name: Vec<u8>,
}

/// A command authorization-area entry to be marshalled into a request.
pub struct AuthCommand {
    /// The authorizing session (or `TPM_RS_PW`).
    pub session_handle: Handle,
    /// `nonceCaller` (empty for a password authorization).
    pub nonce_caller: Vec<u8>,
    /// Session attributes for this command.
    pub attributes: SessionAttributes,
    /// The HMAC (or, for a password authorization, the auth value).
    pub hmac: Vec<u8>,
}

/// A response authorization-area entry parsed from a reply.
pub struct AuthResponse {
    /// The fresh `nonceTPM`.
    pub nonce_tpm: Vec<u8>,
    /// Session attributes echoed by the TPM.
    pub attributes: SessionAttributes,
    /// The response HMAC (empty for a password authorization).
    pub hmac: Vec<u8>,
}

impl Session {
    /// Builds a session handle from the pieces `TPM2_StartAuthSession` returns,
    /// deriving the `sessionKey` by KDFa over `bind_auth || salt`.
    ///
    /// * `bind_auth` — the bind entity's auth value, or empty if unbound.
    /// * `bind_name` — the bind entity's Name, or empty if unbound.
    /// * `salt` — the (decrypted) salt, or empty if unsalted.
    ///
    /// With everything empty this yields an unsalted, unbound session whose
    /// `sessionKey` is empty (authorization still benefits from rolling
    /// nonces and `cpHash` binding).
    pub fn new(
        handle: Handle,
        hash_alg: Alg,
        nonce_tpm: Vec<u8>,
        nonce_caller: Vec<u8>,
        attributes: SessionAttributes,
        bind_auth: &[u8],
        bind_name: &[u8],
        salt: &[u8],
    ) -> Result<Self> {
        let bits = (crypto::digest_size(hash_alg)? * 8) as u32;
        let session_key = if bind_auth.is_empty() && salt.is_empty() {
            Vec::new()
        } else {
            let mut key_in = Vec::with_capacity(bind_auth.len() + salt.len());
            key_in.extend_from_slice(bind_auth);
            key_in.extend_from_slice(salt);
            crypto::kdfa(hash_alg, &key_in, b"ATH", &nonce_tpm, &nonce_caller, bits)?
        };
        Ok(Session {
            handle,
            hash_alg,
            attributes,
            session_key,
            nonce_tpm,
            nonce_caller,
            bound_name: bind_name.to_vec(),
        })
    }

    /// The HMAC key for authorizing an object with auth value `auth_value`:
    /// `sessionKey || authValue`, dropping `authValue` when the object is the
    /// session's bind entity (matched by `object_name`).
    fn hmac_key(&self, auth_value: &[u8], object_name: &[u8]) -> Vec<u8> {
        let bound = !self.bound_name.is_empty() && self.bound_name == object_name;
        let mut k = self.session_key.clone();
        if !bound {
            k.extend_from_slice(auth_value);
        }
        k
    }

    /// Produces the command authorization entry for a command whose `cpHash`
    /// is given, authorizing object `object_name` with `auth_value`.
    ///
    /// `nonce_caller` must be supplied by the caller (use [`Self::fresh_nonce`]
    /// under `std`); it is recorded for response verification.
    pub fn command_auth(
        &mut self,
        cp_hash: &[u8],
        auth_value: &[u8],
        object_name: &[u8],
        nonce_caller: Vec<u8>,
    ) -> Result<AuthCommand> {
        self.nonce_caller = nonce_caller;
        let key = self.hmac_key(auth_value, object_name);
        let hmac = crypto::hmac_parts(
            self.hash_alg,
            &key,
            &[
                cp_hash,
                &self.nonce_caller,
                &self.nonce_tpm,
                &[self.attributes.0],
            ],
        )?;
        Ok(AuthCommand {
            session_handle: self.handle,
            nonce_caller: self.nonce_caller.clone(),
            attributes: self.attributes,
            hmac,
        })
    }

    /// Verifies a response authorization entry against `rp_hash` and absorbs
    /// the new `nonceTPM`. Returns [`Error::Protocol`] on HMAC mismatch.
    pub fn verify_response(
        &mut self,
        rp_hash: &[u8],
        auth_value: &[u8],
        object_name: &[u8],
        resp: &AuthResponse,
    ) -> Result<()> {
        let key = self.hmac_key(auth_value, object_name);
        let expected = crypto::hmac_parts(
            self.hash_alg,
            &key,
            &[
                rp_hash,
                &resp.nonce_tpm,
                &self.nonce_caller,
                &[resp.attributes.0],
            ],
        )?;
        // Constant-time comparison; lengths must match too.
        if expected.len() != resp.hmac.len()
            || !bool::from(ct_eq(&expected, &resp.hmac))
        {
            return Err(Error::Protocol(alloc::string::String::from(
                "response HMAC verification failed",
            )));
        }
        self.nonce_tpm = resp.nonce_tpm.clone();
        Ok(())
    }

    /// A fresh `nonceCaller` of the session-hash's digest length, drawn from
    /// the OS CSPRNG.
    #[cfg(feature = "std")]
    pub fn fresh_nonce(&self) -> Result<Vec<u8>> {
        use purecrypto::rng::{OsRng, RngCore};
        let n = crypto::digest_size(self.hash_alg)?;
        let mut buf = vec![0u8; n];
        OsRng.fill_bytes(&mut buf);
        Ok(buf)
    }
}

/// Constant-time equality over equal-length slices.
fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    Choice::from((diff == 0) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_name_is_handle_bytes() {
        let h = Handle(0x4000_0001);
        assert_eq!(permanent_name(h), [0x40, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn unbound_unsalted_session_has_empty_key() {
        let s = Session::new(
            Handle(0x0200_0000),
            Alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            SessionAttributes::continue_session(),
            b"",
            b"",
            b"",
        )
        .unwrap();
        assert!(s.session_key.is_empty());
    }

    #[test]
    fn command_and_response_hmac_round_trip() {
        // A self-consistency check: a "TPM" that holds the same key would
        // produce the rpHash HMAC we verify. We simulate that by computing the
        // expected response HMAC with the same routine.
        let mut s = Session::new(
            Handle(0x0200_0000),
            Alg::SHA256,
            vec![0xAA; 32],
            vec![0xBB; 32],
            SessionAttributes::continue_session(),
            b"bindauth",
            b"\x00\x0bobjectname",
            b"",
        )
        .unwrap();
        let auth = b"objauth";
        let other_name = b"\x00\x0bsomeothernm";
        let cp = [0x11u8; 32];
        let nc = vec![0xCC; 32];
        let cmd = s.command_auth(&cp, auth, other_name, nc.clone()).unwrap();
        assert_eq!(cmd.nonce_caller, nc);
        assert_eq!(cmd.hmac.len(), 32);

        // Build the matching response HMAC the way the TPM would, then verify.
        let rp = [0x22u8; 32];
        let new_tpm = vec![0xDD; 32];
        let key = s.hmac_key(auth, other_name);
        let resp_hmac = crypto::hmac_parts(
            Alg::SHA256,
            &key,
            &[&rp, &new_tpm, &nc, &[s.attributes.0]],
        )
        .unwrap();
        let resp = AuthResponse {
            nonce_tpm: new_tpm.clone(),
            attributes: s.attributes,
            hmac: resp_hmac,
        };
        s.verify_response(&rp, auth, other_name, &resp).unwrap();
        assert_eq!(s.nonce_tpm, new_tpm);

        // A tampered HMAC must be rejected.
        let bad = AuthResponse {
            nonce_tpm: new_tpm,
            attributes: s.attributes,
            hmac: vec![0u8; 32],
        };
        assert!(s.verify_response(&rp, auth, other_name, &bad).is_err());
    }

    #[test]
    fn bound_object_drops_auth_value_from_key() {
        let s = Session::new(
            Handle(0x0200_0000),
            Alg::SHA256,
            vec![0xAA; 32],
            vec![0xBB; 32],
            SessionAttributes::empty(),
            b"bindauth",
            b"boundname",
            b"",
        )
        .unwrap();
        // For the bound object, key == sessionKey (no auth appended).
        let k_bound = s.hmac_key(b"ignored", b"boundname");
        assert_eq!(k_bound, s.session_key);
        // For any other object, the auth value is appended.
        let k_other = s.hmac_key(b"xyz", b"other");
        assert_eq!(k_other.len(), s.session_key.len() + 3);
    }
}
