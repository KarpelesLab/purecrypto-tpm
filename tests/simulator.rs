//! Integration tests against a running TPM simulator.
//!
//! These talk to a real TPM (a simulator), so they only run when the
//! environment variable `PURECRYPTO_TPM_SIM` names its data socket
//! (e.g. `127.0.0.1:2321`); otherwise each test prints a skip notice and
//! passes. CI starts `swtpm` and sets the variable; see
//! `.github/workflows/ci.yml`.
//!
//! Start a compatible simulator with, e.g.:
//!
//! ```text
//! swtpm socket --tpm2 --server type=tcp,port=2321 \
//!   --ctrl type=tcp,port=2322 --tpmstate dir=$(mktemp -d) \
//!   --flags not-need-init,startup-clear
//! PURECRYPTO_TPM_SIM=127.0.0.1:2321 cargo test --test simulator
//! ```

use std::sync::{Mutex, MutexGuard};

use purecrypto_tpm::transport::SimulatorTransport;
use purecrypto_tpm::types::constants::{Alg, cap, pt, rh, su};
use purecrypto_tpm::types::handles::Handle;
use purecrypto_tpm::types::structures::{Buffer, Public, SensitiveCreate};
use purecrypto_tpm::{Auth, Tpm};

/// A single simulated TPM must be driven serially: concurrent connections and
/// interleaved commands draw `TPM_RC_RETRY`. cargo runs the tests in this
/// binary on multiple threads, so they take this lock to take turns (CI also
/// passes `--test-threads=1`). Poison is ignored — a panicking test still
/// releases the TPM for the next one.
static TPM_LOCK: Mutex<()> = Mutex::new(());

/// Connects a `Tpm` to the simulator named by `PURECRYPTO_TPM_SIM`, or returns
/// `None` (with a printed notice) if the variable is unset. The returned guard
/// must be held for the duration of the test to keep access serialized.
fn connect() -> Option<(Tpm<SimulatorTransport>, MutexGuard<'static, ()>)> {
    let addr = match std::env::var("PURECRYPTO_TPM_SIM") {
        Ok(a) if !a.is_empty() => a,
        _ => {
            eprintln!("PURECRYPTO_TPM_SIM not set; skipping simulator integration test");
            return None;
        }
    };
    let guard = TPM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sim = SimulatorTransport::connect(&addr).expect("connect to simulator");
    let mut tpm = Tpm::new(sim);
    // swtpm started with `startup-clear` is already initialised; ignore the
    // resulting TPM_RC_INITIALIZE if so.
    let _ = tpm.startup(su::CLEAR);
    Some((tpm, guard))
}

#[test]
fn randomness_and_capability() {
    let Some((mut tpm, _guard)) = connect() else {
        return;
    };

    let r = tpm.get_random(24).expect("get_random");
    assert!(!r.is_empty() && r.len() <= 24, "got {} bytes", r.len());

    // TPM_PT_MANUFACTURER is one fixed property; ask for a small window.
    let cap = tpm
        .get_capability(cap::TPM_PROPERTIES, pt::MANUFACTURER, 8)
        .expect("get_capability");
    assert_eq!(cap.capability, cap::TPM_PROPERTIES);
    assert!(!cap.data.is_empty());
}

#[test]
fn pcr_read_sha256_bank() {
    let Some((mut tpm, _guard)) = connect() else {
        return;
    };

    // PCR 0 in the SHA-256 bank should read back a digest-sized value.
    let v = tpm.pcr_read_one(Alg::SHA256, 0).expect("pcr_read");
    if let Some(d) = v {
        assert_eq!(d.len(), 32, "SHA-256 PCR should be 32 bytes");
    }
}

#[test]
fn seal_unseal_password() {
    let Some((mut tpm, _guard)) = connect() else {
        return;
    };

    let parent = tpm
        .create_primary(
            Handle(rh::OWNER),
            &SensitiveCreate::default(),
            &Public::ecc_storage_parent(Alg::SHA256),
            &mut Auth::Password(b""),
        )
        .expect("create_primary");

    let secret = b"password-sealed secret";
    let sensitive = SensitiveCreate {
        user_auth: Buffer::from(&b"seal-pw"[..]),
        data: Buffer::from(&secret[..]),
    };

    let blob = tpm
        .create(
            parent.handle,
            parent.name.as_slice(),
            &sensitive,
            &Public::sealed_data(Alg::SHA256),
            &mut Auth::Password(b""),
        )
        .expect("create");

    let obj = tpm
        .load(
            parent.handle,
            parent.name.as_slice(),
            &blob.private,
            &blob.public,
            &mut Auth::Password(b""),
        )
        .expect("load");

    let out = tpm
        .unseal(
            obj.handle,
            obj.name.as_slice(),
            &mut Auth::Password(b"seal-pw"),
        )
        .expect("unseal");
    assert_eq!(out, secret);

    // Wrong password must be rejected by the TPM.
    let bad = tpm.unseal(
        obj.handle,
        obj.name.as_slice(),
        &mut Auth::Password(b"wrong"),
    );
    assert!(bad.is_err(), "unseal with wrong password should fail");

    tpm.flush_context(obj.handle).expect("flush obj");
    tpm.flush_context(parent.handle).expect("flush parent");
}

#[test]
fn seal_unseal_hmac_session() {
    let Some((mut tpm, _guard)) = connect() else {
        return;
    };

    let parent = tpm
        .create_primary(
            Handle(rh::OWNER),
            &SensitiveCreate::default(),
            &Public::ecc_storage_parent(Alg::SHA256),
            &mut Auth::Password(b""),
        )
        .expect("create_primary");

    let secret = b"hmac-session sealed secret";
    let sensitive = SensitiveCreate {
        user_auth: Buffer::from(&b"sk"[..]),
        data: Buffer::from(&secret[..]),
    };

    let blob = tpm
        .create(
            parent.handle,
            parent.name.as_slice(),
            &sensitive,
            &Public::sealed_data(Alg::SHA256),
            &mut Auth::Password(b""),
        )
        .expect("create");

    let obj = tpm
        .load(
            parent.handle,
            parent.name.as_slice(),
            &blob.private,
            &blob.public,
            &mut Auth::Password(b""),
        )
        .expect("load");

    // Unseal over an unbound HMAC session: the auth value is proven via HMAC,
    // never sent, and the response HMAC is verified by `Session`.
    let mut session = tpm.start_hmac_session(Alg::SHA256).expect("start session");
    let out = tpm
        .unseal(
            obj.handle,
            obj.name.as_slice(),
            &mut Auth::Session {
                session: &mut session,
                auth_value: b"sk",
            },
        )
        .expect("unseal over HMAC session");
    assert_eq!(out, secret);

    tpm.flush_context(session.handle).expect("flush session");
    tpm.flush_context(obj.handle).expect("flush obj");
    tpm.flush_context(parent.handle).expect("flush parent");
}
