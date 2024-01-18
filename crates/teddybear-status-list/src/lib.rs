pub mod credential;

use std::io;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bitvec::{bitbox, boxed::BitBox, vec::BitVec};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use rand::{thread_rng, Rng};
use serde::{de, Deserialize, Deserializer, Serialize};

const ENCODE_BUF_INIT_CAPACITY: usize = 1536;
const RNG_SAMPLE_ATTEMPTS: usize = 25;
const INIT_SIZE: usize = 131_072;

#[derive(PartialEq, Eq, Debug)]
pub struct StatusList {
    inner: BitBox,
}

impl StatusList {
    pub fn encode(&self) -> String {
        let mut buf = Vec::with_capacity(ENCODE_BUF_INIT_CAPACITY);

        {
            let mut encoder = GzEncoder::new(&mut buf, Compression::fast());
            io::copy(&mut &*self.inner, &mut encoder)
                .expect("copying to in-memory buffer should not fail");
        }

        URL_SAFE_NO_PAD.encode(buf)
    }

    pub fn decode(encoded: &str) -> Option<Self> {
        let mut buf = Vec::with_capacity(ENCODE_BUF_INIT_CAPACITY);

        URL_SAFE_NO_PAD.decode_vec(encoded, &mut buf).ok()?;
        let mut decoder = GzDecoder::new(&*buf);
        let mut inner = BitVec::with_capacity(INIT_SIZE);
        io::copy(&mut decoder, &mut inner).ok()?;

        Some(StatusList {
            inner: inner.into_boxed_bitslice(),
        })
    }

    #[inline]
    pub fn is_set(&self, idx: usize) -> bool {
        self.inner.get(idx).map(|val| *val).unwrap_or(false)
    }

    #[inline]
    pub fn set(&mut self, idx: usize) -> bool {
        let Some(mut bit) = self.inner.get_mut(idx) else {
            return false;
        };

        bit.set(true);

        true
    }

    #[inline]
    pub fn set_random(&mut self) -> usize {
        let mut rng = thread_rng();

        for _ in 0..RNG_SAMPLE_ATTEMPTS {
            // FIXME: Possible sampling optimizations.
            let idx = rng.gen_range(0..self.inner.len());

            if !self.is_set(idx) {
                self.inner.set(idx, true);
                return idx;
            }
        }

        self.set_random_with_resize(&mut rng)
    }

    #[cold]
    #[inline]
    fn set_random_with_resize<R: Rng>(&mut self, rng: &mut R) -> usize {
        let start = self.resize();
        let idx = rng.gen_range(start..start * 2);
        self.inner.set(idx, true);
        idx
    }

    #[inline]
    fn resize(&mut self) -> usize {
        let start = self.inner.len();

        let mut resized = bitbox![0; start * 2];

        resized[0..start].copy_from_bitslice(&self.inner);

        self.inner = resized;

        start
    }
}

impl Default for StatusList {
    fn default() -> Self {
        StatusList {
            inner: bitbox![0; INIT_SIZE],
        }
    }
}

impl Serialize for StatusList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for StatusList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;

        StatusList::decode(&encoded).ok_or(de::Error::invalid_value(
            de::Unexpected::Other("string value"),
            &"a base64-encoded gzipped bit array",
        ))
    }
}

#[cfg(test)]
mod tests {
    use bitvec::bitbox;

    use crate::StatusList;

    #[test]
    fn set_random() {
        let mut list = StatusList::default();
        let idx = list.set_random();
        assert!(list.is_set(idx));
    }

    #[test]
    fn set() {
        let mut list = StatusList::default();
        assert!(!list.is_set(123));
        list.set(123);
        assert!(list.is_set(123));
    }

    #[test]
    fn issue_with_resize() {
        let mut list = StatusList {
            inner: bitbox![1; 1],
        };

        assert!(list.set_random() >= 1);
    }

    #[test]
    fn encode_and_decode() {
        let mut first_list = StatusList::default();

        for _ in 0..10 {
            first_list.set_random();
        }

        let encoded = first_list.encode();

        let second_list = StatusList::decode(&encoded).unwrap();

        assert_eq!(first_list, second_list);
    }
}
