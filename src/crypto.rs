//! The crypto the session layer needs, dispatched by `TPM_ALG_ID` over the
//! sibling [`purecrypto`] crate.
//!
//! TPM authorization is hash-agile: the name algorithm and a session's hash
//! pick which digest computes object Names, `cpHash`/`rpHash`, HMAC keys and
//! KDFa output. These helpers fan a runtime [`Alg`] out to the right
//! compile-time `purecrypto` type, and implement **KDFa** (TPM 2.0 Library,
//! Part 1, §11.4.10.2) and the **AES-CFB** parameter-encryption transform on
//! top.

use alloc::vec::Vec;

use purecrypto::cipher::{Aes128, Aes256, Cfb};
use purecrypto::hash::{Digest, Hmac, Sha1, Sha256, Sha384, Sha512, Sm3};

use crate::error::{Error, Result};
use crate::types::constants::Alg;

/// Hashes the concatenation of `parts` with `alg`. Used for object Names,
/// `cpHash`/`rpHash` and policy digests, all of which hash several fields in
/// sequence.
pub fn hash_parts(alg: Alg, parts: &[&[u8]]) -> Result<Vec<u8>> {
    fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().as_ref().to_vec()
    }
    Ok(match alg {
        Alg::SHA1 => run::<Sha1>(parts),
        Alg::SHA256 => run::<Sha256>(parts),
        Alg::SHA384 => run::<Sha384>(parts),
        Alg::SHA512 => run::<Sha512>(parts),
        Alg::SM3_256 => run::<Sm3>(parts),
        _ => return Err(Error::Usage("unsupported hash algorithm")),
    })
}

/// Convenience: hash a single byte string with `alg`.
#[allow(dead_code)] // used by tests and forthcoming policy helpers
pub fn hash(alg: Alg, data: &[u8]) -> Result<Vec<u8>> {
    hash_parts(alg, &[data])
}

/// HMAC over the concatenation of `parts`, keyed by `key`, using `alg`'s hash.
pub fn hmac_parts(alg: Alg, key: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    fn run<D: Digest>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut m = Hmac::<D>::new(key);
        for p in parts {
            m.update(p);
        }
        m.finalize().as_ref().to_vec()
    }
    Ok(match alg {
        Alg::SHA1 => run::<Sha1>(key, parts),
        Alg::SHA256 => run::<Sha256>(key, parts),
        Alg::SHA384 => run::<Sha384>(key, parts),
        Alg::SHA512 => run::<Sha512>(key, parts),
        Alg::SM3_256 => run::<Sm3>(key, parts),
        _ => return Err(Error::Usage("unsupported HMAC hash algorithm")),
    })
}

/// The digest size of `alg` in bytes, or a usage error for a non-hash alg.
pub fn digest_size(alg: Alg) -> Result<usize> {
    alg.digest_size()
        .filter(|&n| n > 0)
        .ok_or(Error::Usage("not a hash algorithm"))
}

/// **KDFa** — the TPM's SP 800-108 counter-mode KDF (Part 1, §11.4.10.2).
///
/// Produces `bits` bits of key material:
///
/// ```text
/// K_i = HMAC_alg(key, UINT32(i) || label || 0x00 || context_u || context_v || UINT32(bits))
/// ```
///
/// for `i = 1, 2, …`, concatenated and truncated to `ceil(bits/8)` bytes; if
/// `bits` is not a multiple of 8 the surplus high bits of the leading octet
/// are masked off. A `0x00` terminator is appended to `label` per spec.
pub fn kdfa(
    alg: Alg,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Result<Vec<u8>> {
    let out_len = (bits as usize).div_ceil(8);
    let mut out = Vec::with_capacity(out_len);
    let bits_be = bits.to_be_bytes();
    let mut counter: u32 = 0;
    while out.len() < out_len {
        counter += 1;
        let ctr_be = counter.to_be_bytes();
        let block = hmac_parts(
            alg,
            key,
            &[
                &ctr_be,
                label,
                &[0x00],
                context_u,
                context_v,
                &bits_be,
            ],
        )?;
        out.extend_from_slice(&block);
    }
    out.truncate(out_len);
    // Mask surplus high bits of the leading octet when bits isn't byte-aligned.
    let rem = bits % 8;
    if rem != 0 && !out.is_empty() {
        out[0] &= 0xFFu8 >> (8 - rem);
    }
    Ok(out)
}

/// In-place AES-CFB transform for session parameter encryption (`TPM_ALG_CFB`).
///
/// `key` selects AES-128 or AES-256 by length; `iv` is the 16-byte CFB IV that
/// KDFa derives alongside the key. `encrypt` chooses direction. Any other key
/// length is a usage error.
#[allow(dead_code)] // wired in once session parameter encryption lands
pub fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) -> Result<()> {
    match key.len() {
        16 => {
            let mut c = Cfb::new(Aes128::new(key.try_into().expect("16")), iv);
            if encrypt {
                c.encrypt(data);
            } else {
                c.decrypt(data);
            }
        }
        32 => {
            let mut c = Cfb::new(Aes256::new(key.try_into().expect("32")), iv);
            if encrypt {
                c.encrypt(data);
            } else {
                c.decrypt(data);
            }
        }
        _ => return Err(Error::Usage("unsupported AES key size for CFB")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256 of "abc" (FIPS 180-4 worked example).
    #[test]
    fn sha256_abc() {
        let d = hash(Alg::SHA256, b"abc").unwrap();
        assert_eq!(
            d,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    // KDFa is SP 800-108 counter mode; the output length and bit-masking are
    // the parts most likely to regress. Spot-check both.
    #[test]
    fn kdfa_length_and_masking() {
        let k = kdfa(Alg::SHA256, b"key", b"LABEL", b"", b"", 128).unwrap();
        assert_eq!(k.len(), 16);

        // 12 bits => 2 bytes, top 4 bits of the leading octet cleared.
        let k = kdfa(Alg::SHA256, b"key", b"LABEL", b"", b"", 12).unwrap();
        assert_eq!(k.len(), 2);
        assert_eq!(k[0] & 0xF0, 0);

        // Output longer than one SHA-256 block must span multiple HMAC calls
        // and still be exact length.
        let k = kdfa(Alg::SHA256, b"key", b"LABEL", b"ctx", b"", 512).unwrap();
        assert_eq!(k.len(), 64);
    }

    #[test]
    fn aes_cfb_round_trips() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let mut buf = *b"sixteen byte msg";
        let orig = buf;
        aes_cfb(&key, &iv, &mut buf, true).unwrap();
        assert_ne!(buf, orig);
        aes_cfb(&key, &iv, &mut buf, false).unwrap();
        assert_eq!(buf, orig);
    }
}
