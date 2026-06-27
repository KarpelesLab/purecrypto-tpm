//! The object lifecycle: create a primary, create a child, load it, unseal it.
//!
//! Together these implement the canonical **sealing** flow: create a restricted
//! storage parent under a hierarchy, `Create` a sealed-data object under that
//! parent, `Load` it back, then `Unseal` to recover the secret — each step
//! authorized by a password or HMAC session.

use alloc::vec::Vec;

use crate::commands::{CreatePrimaryResult, CreateResult, LoadResult};
use crate::error::Result;
use crate::marshal::{Marshal, Reader, marshal_tpm2b};
use crate::session::permanent_name;
use crate::tpm::{Auth, Tpm};
use crate::transport::Transport;
use crate::types::constants::cc;
use crate::types::handles::Handle;
use crate::types::structures::{
    Buffer, PcrSelectionList, Public, SensitiveCreate, skip_tk_creation,
};

impl<T: Transport> Tpm<T> {
    /// `TPM2_CreatePrimary` — create and load a primary object directly under
    /// `hierarchy` (e.g. [`rh::OWNER`](crate::types::constants::rh::OWNER) or
    /// [`rh::NULL`](crate::types::constants::rh::NULL)).
    ///
    /// `sensitive` carries the new object's auth value (and, for sealed data,
    /// the data to seal); `public` is the object template. `auth` authorizes
    /// the hierarchy.
    pub fn create_primary(
        &mut self,
        hierarchy: Handle,
        sensitive: &SensitiveCreate,
        public: &Public,
        auth: &mut Auth<'_>,
    ) -> Result<CreatePrimaryResult> {
        let p = create_params(sensitive, public);
        let name = permanent_name(hierarchy);
        let resp = self.run(cc::CREATE_PRIMARY, &[hierarchy], &[&name], &p, auth, 1)?;

        let handle = resp.handles[0];
        let mut r = Reader::new(&resp.params);
        let out_public = Buffer(r.tpm2b()?.to_vec()); // outPublic
        let _creation_data = r.tpm2b()?; // creationData
        let _creation_hash = r.tpm2b()?; // creationHash
        skip_tk_creation(&mut r)?; // creationTicket
        let obj_name = Buffer(r.tpm2b()?.to_vec()); // name

        Ok(CreatePrimaryResult {
            handle,
            name: obj_name,
            public: out_public,
        })
    }

    /// `TPM2_Create` — create a child object under loaded parent `parent`
    /// (authorized via `auth` with the parent's Name `parent_name`).
    ///
    /// Returns the wrapped private blob and public area to feed to
    /// [`load`](Tpm::load).
    pub fn create(
        &mut self,
        parent: Handle,
        parent_name: &[u8],
        sensitive: &SensitiveCreate,
        public: &Public,
        auth: &mut Auth<'_>,
    ) -> Result<CreateResult> {
        let p = create_params(sensitive, public);
        let resp = self.run(cc::CREATE, &[parent], &[parent_name], &p, auth, 0)?;

        let mut r = Reader::new(&resp.params);
        let private = Buffer(r.tpm2b()?.to_vec()); // outPrivate
        let public = Buffer(r.tpm2b()?.to_vec()); // outPublic
        Ok(CreateResult { private, public })
    }

    /// `TPM2_Load` — load a child object created by [`create`](Tpm::create)
    /// back under its parent, returning its transient handle and Name.
    ///
    /// `in_private` / `in_public` are the [`CreateResult`] buffers; `auth`
    /// authorizes the parent.
    pub fn load(
        &mut self,
        parent: Handle,
        parent_name: &[u8],
        in_private: &Buffer,
        in_public: &Buffer,
        auth: &mut Auth<'_>,
    ) -> Result<LoadResult> {
        let mut p = Vec::new();
        in_private.marshal(&mut p); // TPM2B_PRIVATE
        in_public.marshal(&mut p); // TPM2B_PUBLIC
        let resp = self.run(cc::LOAD, &[parent], &[parent_name], &p, auth, 1)?;

        let handle = resp.handles[0];
        let mut r = Reader::new(&resp.params);
        let name = Buffer(r.tpm2b()?.to_vec());
        Ok(LoadResult { handle, name })
    }

    /// `TPM2_Unseal` — recover the sensitive data of a loaded sealed object
    /// `item` (authorized via `auth` with the item's Name `item_name`).
    pub fn unseal(
        &mut self,
        item: Handle,
        item_name: &[u8],
        auth: &mut Auth<'_>,
    ) -> Result<Vec<u8>> {
        let resp = self.run(cc::UNSEAL, &[item], &[item_name], &[], auth, 0)?;
        let mut r = Reader::new(&resp.params);
        Ok(r.tpm2b()?.to_vec())
    }
}

/// The shared parameter prefix of `Create`/`CreatePrimary`:
/// `inSensitive || inPublic || outsideInfo(empty) || creationPCR(empty)`.
fn create_params(sensitive: &SensitiveCreate, public: &Public) -> Vec<u8> {
    let mut p = Vec::new();
    sensitive.wrap_2b(&mut p); // TPM2B_SENSITIVE_CREATE
    public.wrap_2b(&mut p); // TPM2B_PUBLIC
    marshal_tpm2b(&[], &mut p).ok(); // outsideInfo: empty TPM2B_DATA
    PcrSelectionList::default().marshal(&mut p); // creationPCR: count 0
    p
}
