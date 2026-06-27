//! Big-endian marshalling, the bedrock every TPM structure rests on.
//!
//! TPM 2.0 "canonical form" (Part 1, §3.3.4 and Part 4) is plain big-endian
//! with no padding or alignment: integers in network byte order, fixed arrays
//! laid out in order, and `TPM2B_*` buffers prefixed by a `UINT16` byte count.
//! Discriminated unions (`TPMU_*`) are *not* self-describing — the selector
//! that picks the active member lives in a separate field — so they cannot
//! implement these traits on their own; the enclosing `TPMT_*`/`TPMS_*`
//! structure marshals them given the selector.
//!
//! [`Marshal`] appends to a byte vector; [`Unmarshal`] reads from a [`Reader`]
//! that tracks position and refuses to run off the end.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// A type that can be written in TPM canonical (big-endian) form.
pub trait Marshal {
    /// Appends the canonical encoding of `self` to `out`.
    fn marshal(&self, out: &mut Vec<u8>);

    /// Convenience: marshal into a fresh vector.
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.marshal(&mut v);
        v
    }
}

/// A type that can be parsed from TPM canonical (big-endian) form.
pub trait Unmarshal: Sized {
    /// Reads one value from `r`, advancing it past the bytes consumed.
    fn unmarshal(r: &mut Reader<'_>) -> Result<Self>;
}

/// A bounds-checked cursor over a TPM byte buffer.
///
/// Every read advances [`pos`](Reader::pos) and fails with
/// [`Error::Malformed`] rather than panicking if the buffer is too short, so a
/// truncated or hostile response can never index out of bounds.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wraps `buf` in a reader positioned at its start.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// The number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The current read offset from the start of the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// `true` once every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrows the next `n` bytes without copying, advancing past them.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Malformed("unexpected end of TPM buffer"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads a single byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a `TPM2B`: a big-endian `UINT16` byte count followed by that many
    /// bytes, returned by reference.
    pub fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}

macro_rules! prim {
    ($($t:ty),*) => {$(
        impl Marshal for $t {
            #[inline]
            fn marshal(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
        }
        impl Unmarshal for $t {
            #[inline]
            fn unmarshal(r: &mut Reader<'_>) -> Result<Self> {
                let b = r.take(core::mem::size_of::<$t>())?;
                Ok(<$t>::from_be_bytes(b.try_into().expect("size checked")))
            }
        }
    )*};
}

prim!(u8, u16, u32, u64);

/// Marshals a `TPM2B`: a `UINT16` length prefix followed by `data`.
///
/// Returns [`Error::Malformed`] if `data` is longer than a `UINT16` can
/// describe (65535 bytes), the structural limit of every `TPM2B`.
pub fn marshal_tpm2b(data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| Error::Malformed("TPM2B exceeds 65535 bytes"))?;
    len.marshal(out);
    out.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip() {
        let mut out = Vec::new();
        0x1122u16.marshal(&mut out);
        0x33445566u32.marshal(&mut out);
        0xAAu8.marshal(&mut out);
        assert_eq!(out, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xAA]);

        let mut r = Reader::new(&out);
        assert_eq!(u16::unmarshal(&mut r).unwrap(), 0x1122);
        assert_eq!(u32::unmarshal(&mut r).unwrap(), 0x33445566);
        assert_eq!(u8::unmarshal(&mut r).unwrap(), 0xAA);
        assert!(r.is_empty());
    }

    #[test]
    fn tpm2b_round_trip() {
        let mut out = Vec::new();
        marshal_tpm2b(&[0xDE, 0xAD, 0xBE, 0xEF], &mut out).unwrap();
        assert_eq!(out, [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);

        let mut r = Reader::new(&out);
        assert_eq!(r.tpm2b().unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(r.is_empty());
    }

    #[test]
    fn short_read_is_error() {
        let mut r = Reader::new(&[0x00]);
        assert!(u32::unmarshal(&mut r).is_err());
    }

    #[test]
    fn tpm2b_overlong_payload_rejected() {
        let big = alloc::vec![0u8; 0x1_0000];
        let mut out = Vec::new();
        assert!(marshal_tpm2b(&big, &mut out).is_err());
    }
}
