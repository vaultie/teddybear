// https://github.com/spruceid/ssi/blob/main/crates/status/src/impl/bitstring_status_list_20240406/mod.rs

use std::{io::Read, time::Duration};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
#[error("invalid status size `{0}`")]
struct InvalidStatusSize(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
struct StatusSize(u8);

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 8 {
            Ok(Self(value))
        } else {
            Err(InvalidStatusSize(value))
        }
    }
}

impl Default for StatusSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl StatusSize {
    pub const DEFAULT: Self = Self(1);

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }

    fn offset_of(&self, index: usize) -> Offset {
        let bit_offset = self.0 as usize * index;
        Offset {
            byte: bit_offset / 8,
            bit: bit_offset % 8,
        }
    }

    fn mask(&self) -> u8 {
        if self.0 == 8 { 0xff } else { (1 << self.0) - 1 }
    }
}

impl<'de> Deserialize<'de> for StatusSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u8::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Maximum duration, in milliseconds, an implementer is allowed to cache a
/// status list.
///
/// Default value is 300000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeToLive(pub u64);

impl Default for TimeToLive {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TimeToLive {
    pub const DEFAULT: Self = Self(300000);

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }
}

impl From<TimeToLive> for Duration {
    fn from(value: TimeToLive) -> Self {
        Duration::from_millis(value.0)
    }
}

#[derive(Debug)]
struct Offset {
    byte: usize,
    bit: usize,
}

impl Offset {
    fn left_shift(&self, status_size: StatusSize) -> (i32, Option<u32>) {
        let high = (8 - status_size.0 as isize - self.bit as isize) as i32;
        let low = if high < 0 {
            Some((8 + high) as u32)
        } else {
            None
        };

        (high, low)
    }
}

#[derive(Debug, Clone)]
struct BitString {
    status_size: StatusSize,
    bytes: Vec<u8>,
    len: usize,
}

impl BitString {
    /// Creates a bit-string from a byte array and status size.
    fn from_bytes(status_size: StatusSize, bytes: Vec<u8>) -> Self {
        let len = bytes.len() * 8usize / status_size.0 as usize;
        Self {
            status_size,
            bytes,
            len,
        }
    }

    /// Returns the value stored in the list at the given index.
    fn get(&self, index: usize) -> Option<u8> {
        if index >= self.len {
            return None;
        }

        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        Some(self.get_at(offset.byte, high_shift, low_shift))
    }

    fn get_at(&self, byte_offset: usize, high_shift: i32, low_shift: Option<u32>) -> u8 {
        let high = self
            .bytes
            .get(byte_offset)
            .unwrap()
            .overflowing_signed_shr(high_shift)
            .0;

        let low = match low_shift {
            Some(low_shift) => {
                self.bytes
                    .get(byte_offset + 1)
                    .unwrap()
                    .overflowing_shr(low_shift)
                    .0
            }
            None => 0,
        };

        (high | low) & self.status_size.mask()
    }
}

trait OverflowingSignedShift: Sized {
    fn overflowing_signed_shr(self, shift: i32) -> (Self, bool);
}

impl OverflowingSignedShift for u8 {
    fn overflowing_signed_shr(self, shift: i32) -> (u8, bool) {
        if shift < 0 {
            self.overflowing_shl(shift.unsigned_abs())
        } else {
            self.overflowing_shr(shift.unsigned_abs())
        }
    }
}

#[derive(Debug, Clone)]
pub struct StatusList {
    bit_string: BitString,
}

impl StatusList {
    fn from_bytes(status_size: StatusSize, bytes: Vec<u8>) -> Self {
        Self {
            bit_string: BitString::from_bytes(status_size, bytes),
        }
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        self.bit_string.get(index)
    }
}

/// Multibase-encoded base64url (with no padding) representation of the
/// GZIP-compressed bitstring values for the associated range of a bitstring
/// status list verifiable credential.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncodedList(String);

impl EncodedList {
    /// Minimum bitstring size (16KB).
    pub const MINIMUM_SIZE: usize = 16 * 1024;

    /// Default maximum bitstring size allowed by the `decode` function.
    ///
    /// 16MB.
    pub const DEFAULT_LIMIT: u64 = 16 * 1024 * 1024;

    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn decode(&self, limit: Option<u64>) -> Option<Vec<u8>> {
        let limit = limit.unwrap_or(Self::DEFAULT_LIMIT);
        let (_base, compressed) = multibase::decode(&self.0).ok()?;
        let mut decoder = GzDecoder::new(compressed.as_slice()).take(limit);
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct BitstringStatusList {
    #[serde(default, skip_serializing_if = "StatusSize::is_default")]
    status_size: StatusSize,

    /// Encoded status list.
    encoded_list: EncodedList,
}

#[derive(thiserror::Error, Debug)]
#[error("invalid bitstring status list")]
pub struct InvalidBitstringStatusList;

impl BitstringStatusList {
    pub fn decode(&self) -> Result<StatusList, InvalidBitstringStatusList> {
        let bytes = self
            .encoded_list
            .decode(None)
            .ok_or(InvalidBitstringStatusList)?;
        Ok(StatusList::from_bytes(self.status_size, bytes))
    }
}
