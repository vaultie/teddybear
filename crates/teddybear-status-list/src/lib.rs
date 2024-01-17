use std::io;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bitvec::{bitbox, boxed::BitBox, slice::BitSlice, vec::BitVec};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

const ENCODE_BUF_INIT_CAPACITY: usize = 1536;
const RNG_SAMPLE_ATTEMPTS: usize = 25;
const INIT_SIZE: usize = 131_072;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedRevocationList {
    pub issued: String,
    pub revoked: String,
}

#[derive(PartialEq, Eq, Debug)]
pub struct RevocationList {
    issued: BitBox,
    revoked: BitBox,
}

impl RevocationList {
    pub fn encode(&self) -> EncodedRevocationList {
        let mut buf = Vec::with_capacity(ENCODE_BUF_INIT_CAPACITY);

        let issued = Self::encode_bit_slice(&self.issued, &mut buf);
        let revoked = Self::encode_bit_slice(&self.revoked, &mut buf);

        EncodedRevocationList { issued, revoked }
    }

    #[inline]
    fn encode_bit_slice<T: AsRef<BitSlice>>(val: &T, buf: &mut Vec<u8>) -> String {
        buf.clear();

        {
            let mut encoder = GzEncoder::new(&mut *buf, Compression::fast());
            io::copy(&mut val.as_ref(), &mut encoder)
                .expect("copying to in-memory buffer should not fail");
        }

        URL_SAFE_NO_PAD.encode(buf)
    }

    pub fn decode(encoded: &EncodedRevocationList) -> Option<Self> {
        let mut buf = Vec::with_capacity(ENCODE_BUF_INIT_CAPACITY);

        let issued = Self::decode_string(&encoded.issued, &mut buf)?;
        let revoked = Self::decode_string(&encoded.revoked, &mut buf)?;

        Some(RevocationList {
            issued: issued.into_boxed_bitslice(),
            revoked: revoked.into_boxed_bitslice(),
        })
    }

    #[inline]
    fn decode_string<T: AsRef<[u8]>>(val: &T, buf: &mut Vec<u8>) -> Option<BitVec> {
        buf.clear();
        URL_SAFE_NO_PAD.decode_vec(val, buf).ok()?;
        let mut decoder = GzDecoder::new(&**buf);
        let mut bits = BitVec::with_capacity(INIT_SIZE);
        io::copy(&mut decoder, &mut bits).ok()?;
        Some(bits)
    }

    pub fn is_revoked(&self, idx: usize) -> bool {
        self.revoked.get(idx).map(|val| *val).unwrap_or(false)
    }

    pub fn issue(&mut self) -> usize {
        let mut rng = thread_rng();

        for _ in 0..RNG_SAMPLE_ATTEMPTS {
            // FIXME: Possible sampling optimizations.
            let idx = rng.gen_range(0..self.issued.len());

            if !self.exists(idx) {
                self.issued.set(idx, true);
                return idx;
            }
        }

        self.issue_with_resize(&mut rng)
    }

    pub fn revoke(&mut self, idx: usize) -> bool {
        assert!(self.issued.len() == self.revoked.len());

        if self.exists(idx) {
            self.revoked.set(idx, true);
            true
        } else {
            false
        }
    }

    #[cold]
    fn issue_with_resize<R: Rng>(&mut self, rng: &mut R) -> usize {
        let start = self.resize();
        let idx = rng.gen_range(start..start * 2);
        self.issued.set(idx, true);
        idx
    }

    fn resize(&mut self) -> usize {
        assert!(self.issued.len() == self.revoked.len());

        let start = self.issued.len();

        let mut issued = bitbox![0; self.issued.len() * 2];
        let mut revoked = bitbox![0; self.revoked.len() * 2];

        issued[0..self.issued.len()].copy_from_bitslice(&self.issued);
        revoked[0..self.revoked.len()].copy_from_bitslice(&self.revoked);

        self.issued = issued;
        self.revoked = revoked;

        start
    }

    #[inline]
    fn exists(&self, idx: usize) -> bool {
        self.issued.get(idx).map(|val| *val).unwrap_or(false)
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        RevocationList {
            issued: bitbox![0; INIT_SIZE],
            revoked: bitbox![0; INIT_SIZE],
        }
    }
}

#[cfg(test)]
mod tests {
    use bitvec::bitbox;

    use crate::RevocationList;

    #[test]
    fn issue_and_revoke() {
        let mut list = RevocationList::default();
        let idx = list.issue();
        assert!(!list.is_revoked(idx));
        assert!(list.revoke(idx));
        assert!(list.is_revoked(idx));
    }

    #[test]
    fn non_existent_id() {
        let mut list = RevocationList::default();
        assert!(!list.revoke(123));
        assert!(!list.is_revoked(123));
    }

    #[test]
    fn resize() {
        let mut list = RevocationList::default();
        let current_length = list.issued.len();
        assert!(list.resize() == current_length);
    }

    #[test]
    fn issue_with_resize() {
        let mut list = RevocationList {
            issued: bitbox![1; 1],
            revoked: bitbox![1; 1],
        };

        assert!(list.issue() >= 1);
    }

    #[test]
    fn encode_and_decode() {
        let mut first_list = RevocationList::default();

        for _ in 0..10 {
            let idx = first_list.issue();
            first_list.revoke(idx);
        }

        let encoded = first_list.encode();

        let second_list = RevocationList::decode(&encoded).unwrap();

        assert_eq!(first_list, second_list);
    }
}
