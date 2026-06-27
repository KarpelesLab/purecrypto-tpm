//! The command dispatcher: builds request frames, runs them over a
//! [`Transport`], checks the response code and parses the reply.
//!
//! [`Tpm`] owns a transport and exposes typed command methods (in
//! [`crate::commands`], implemented as `impl Tpm` blocks). The low-level
//! [`Tpm::run`] here is what those methods build on: it lays out the
//! tag/size/code header, the handle area, an optional authorization area, and
//! the parameter area, then unframes the response — verifying the session HMAC
//! when an HMAC session authorizes the command.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::marshal::{Marshal, Reader, Unmarshal, marshal_tpm2b};
use crate::session::{AuthResponse, Session};
use crate::transport::Transport;
use crate::types::attributes::SessionAttributes;
use crate::types::constants::{rh, st};
use crate::types::handles::Handle;
use crate::{crypto, types::constants::Alg};

/// How a command is authorized.
pub enum Auth<'a> {
    /// No authorization area (`TPM_ST_NO_SESSIONS`).
    None,
    /// A password authorization (`TPM_RS_PW`) carrying the auth value in the
    /// clear. Suitable over a trusted local bus.
    Password(&'a [u8]),
    /// An HMAC session authorization. `auth_value` is the auth of the object
    /// being authorized (the first command handle); the session proves
    /// knowledge of it without transmitting it.
    Session {
        /// The established session (mutated as the nonce chain advances).
        session: &'a mut Session,
        /// The auth value of the authorized object.
        auth_value: &'a [u8],
    },
}

impl Auth<'_> {
    fn uses_session_area(&self) -> bool {
        !matches!(self, Auth::None)
    }
}

/// A parsed, success-checked response: the response handles and the raw
/// parameter bytes (to be unmarshalled by the calling command).
pub(crate) struct RawResponse {
    pub handles: Vec<Handle>,
    pub params: Vec<u8>,
}

/// A TPM, reached through some [`Transport`].
pub struct Tpm<T: Transport> {
    transport: T,
}

impl<T: Transport> Tpm<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Tpm { transport }
    }

    /// Borrows the underlying transport (e.g. to power on a simulator).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the `Tpm`, returning the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Runs one command and returns its parsed response.
    ///
    /// * `code` — the `TPM_CC`.
    /// * `handles` — the handle-area handles, in spec order.
    /// * `names` — the Name of each handle in `handles` (for `cpHash`); use
    ///   [`crate::session::permanent_name`] for permanent/PCR handles and the
    ///   load-time Name for objects. Only consulted for HMAC sessions.
    /// * `params` — the marshalled parameter area.
    /// * `auth` — how the command is authorized.
    /// * `resp_handles` — how many handles the response carries.
    pub(crate) fn run(
        &mut self,
        code: u32,
        handles: &[Handle],
        names: &[&[u8]],
        params: &[u8],
        auth: &mut Auth<'_>,
        resp_handles: usize,
    ) -> Result<RawResponse> {
        let use_sessions = auth.uses_session_area();

        let mut body = Vec::new();
        for h in handles {
            h.marshal(&mut body);
        }

        if use_sessions {
            let mut area = Vec::new();
            match auth {
                Auth::None => unreachable!(),
                Auth::Password(pw) => {
                    Handle(rh::PW).marshal(&mut area);
                    marshal_tpm2b(&[], &mut area).ok(); // empty nonceCaller
                    area.push(SessionAttributes::CONTINUE_SESSION);
                    marshal_tpm2b(pw, &mut area)
                        .map_err(|_| Error::Usage("auth value too long"))?;
                }
                Auth::Session {
                    session,
                    auth_value,
                } => {
                    let object_name = names.first().copied().unwrap_or(&[]);
                    let cp = cp_hash(session.hash_alg, code, names, params)?;
                    let nonce = session_nonce(session)?;
                    let ac = session.command_auth(&cp, auth_value, object_name, nonce)?;
                    ac.session_handle.marshal(&mut area);
                    marshal_tpm2b(&ac.nonce_caller, &mut area).ok();
                    area.push(ac.attributes.0);
                    marshal_tpm2b(&ac.hmac, &mut area).ok();
                }
            }
            (area.len() as u32).marshal(&mut body);
            body.extend_from_slice(&area);
        }

        body.extend_from_slice(params);

        let tag = if use_sessions {
            st::SESSIONS
        } else {
            st::NO_SESSIONS
        };
        let total = 10u32 + body.len() as u32;
        let mut frame = Vec::with_capacity(total as usize);
        tag.marshal(&mut frame);
        total.marshal(&mut frame);
        code.marshal(&mut frame);
        frame.extend_from_slice(&body);

        let resp = self.transport.transmit(&frame)?;
        self.parse_response(code, &resp, auth, names, resp_handles)
    }

    fn parse_response(
        &mut self,
        code: u32,
        resp: &[u8],
        auth: &mut Auth<'_>,
        names: &[&[u8]],
        resp_handles: usize,
    ) -> Result<RawResponse> {
        let mut r = Reader::new(resp);
        let tag = r.u16()?;
        let size = r.u32()? as usize;
        let rc = r.u32()?;
        if rc != 0 {
            return Err(Error::rc(rc));
        }
        if size != resp.len() {
            return Err(Error::Protocol(String::from(
                "response size header disagrees with received length",
            )));
        }

        let mut rhandles = Vec::with_capacity(resp_handles);
        for _ in 0..resp_handles {
            rhandles.push(Handle::unmarshal(&mut r)?);
        }

        let params = if tag == st::SESSIONS {
            let param_size = r.u32()? as usize;
            let pbytes = r.take(param_size)?.to_vec();
            // The response authorization area follows the parameters.
            let auth_resp = parse_auth_response(&mut r)?;
            if let Auth::Session {
                session,
                auth_value,
            } = auth
            {
                let object_name = names.first().copied().unwrap_or(&[]);
                let rp = rp_hash(session.hash_alg, rc, code, &pbytes)?;
                session.verify_response(&rp, auth_value, object_name, &auth_resp)?;
            }
            pbytes
        } else {
            r.take(r.remaining())?.to_vec()
        };

        Ok(RawResponse {
            handles: rhandles,
            params,
        })
    }
}

/// `cpHash = H(commandCode || Name(handle)... || parameters)`.
fn cp_hash(alg: Alg, code: u32, names: &[&[u8]], params: &[u8]) -> Result<Vec<u8>> {
    let code_be = code.to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(names.len() + 2);
    parts.push(&code_be);
    parts.extend_from_slice(names);
    parts.push(params);
    crypto::hash_parts(alg, &parts)
}

/// `rpHash = H(responseCode || commandCode || parameters)`.
fn rp_hash(alg: Alg, rc: u32, code: u32, params: &[u8]) -> Result<Vec<u8>> {
    let rc_be = rc.to_be_bytes();
    let code_be = code.to_be_bytes();
    crypto::hash_parts(alg, &[&rc_be, &code_be, params])
}

fn parse_auth_response(r: &mut Reader<'_>) -> Result<AuthResponse> {
    let nonce_tpm = r.tpm2b()?.to_vec();
    let attributes = SessionAttributes(r.u8()?);
    let hmac = r.tpm2b()?.to_vec();
    Ok(AuthResponse {
        nonce_tpm,
        attributes,
        hmac,
    })
}

#[cfg(feature = "std")]
fn session_nonce(session: &Session) -> Result<Vec<u8>> {
    session.fresh_nonce()
}

#[cfg(not(feature = "std"))]
fn session_nonce(_session: &Session) -> Result<Vec<u8>> {
    Err(Error::Usage(
        "HMAC sessions need a nonceCaller source; enable `std` or supply nonces manually",
    ))
}
