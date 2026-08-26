//! Widevine `pssh` box generation and parsing.
//!
//! A `pssh` box (ISO/IEC 23001-7, "Protection System Specific Header") is the
//! ISO-BMFF box that carries DRM initialisation data. Players hand its bytes
//! to the CDM, packagers write it into the `moov` of a CMAF/DASH asset, and
//! MPDs carry it base64-encoded inside a `<cenc:pssh>` element.
//!
//! The parser here is deliberately system-agnostic: it will read a PlayReady
//! or a generic box too, and reports the system ID it found rather than
//! rejecting it. [`PsshBox::is_widevine`] is the Widevine check.
//!
//! ```
//! use drm_primitives::widevine::{PsshBox, WIDEVINE_SYSTEM_ID};
//!
//! # fn main() -> Result<(), drm_primitives::Error> {
//! let key_id = [0x0a; 16];
//! let bytes = PsshBox::widevine_v1(&[key_id]).to_bytes();
//!
//! let parsed = PsshBox::parse(&bytes)?;
//! assert!(parsed.is_widevine());
//! assert_eq!(parsed.system_id, WIDEVINE_SYSTEM_ID);
//! assert_eq!(parsed.key_ids, vec![key_id]);
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};

/// The Widevine DRM system ID, `edef8ba9-79d6-4ace-a3c8-27dcd51d21ed`.
///
/// Registered with the DASH-IF system ID registry; every Widevine `pssh` box
/// carries it in bytes 12..28.
pub const WIDEVINE_SYSTEM_ID: [u8; 16] = [
    0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, 0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED,
];

/// The length of a CENC key ID, in bytes. Key IDs are UUIDs.
pub const KEY_ID_LEN: usize = 16;

/// The fixed part of a `pssh` box: size, type, version, flags and system ID.
const HEADER_LEN: usize = 32;

/// A parsed — or about to be serialised — `pssh` box.
///
/// Version 0 boxes carry only an opaque `data` payload, which for Widevine is
/// a protobuf this crate does not decode. Version 1 boxes additionally list
/// their key IDs in the clear, which is the part a packager or a key service
/// can actually use without a protobuf decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsshBox {
    /// Box version. Only `0` and `1` are defined; only version 1 carries key IDs.
    pub version: u8,
    /// The 24-bit box flags. Always zero in practice.
    pub flags: [u8; 3],
    /// The DRM system this box is for. Compare against [`WIDEVINE_SYSTEM_ID`].
    pub system_id: [u8; 16],
    /// The key IDs listed in the box. Always empty for a version 0 box.
    pub key_ids: Vec<[u8; KEY_ID_LEN]>,
    /// The system-specific payload. For Widevine this is a protobuf; this
    /// crate carries it verbatim and does not interpret it.
    pub data: Vec<u8>,
}

impl PsshBox {
    /// Build a Widevine version 1 box listing the given key IDs and no payload.
    ///
    /// This is the form that is useful without a protobuf encoder: the key IDs
    /// are readable directly out of the box.
    ///
    /// ```
    /// use drm_primitives::widevine::PsshBox;
    ///
    /// let bytes = PsshBox::widevine_v1(&[[1u8; 16], [2u8; 16]]).to_bytes();
    /// assert_eq!(&bytes[4..8], b"pssh");
    /// ```
    pub fn widevine_v1(key_ids: &[[u8; KEY_ID_LEN]]) -> Self {
        Self {
            version: 1,
            flags: [0; 3],
            system_id: WIDEVINE_SYSTEM_ID,
            key_ids: key_ids.to_vec(),
            data: Vec::new(),
        }
    }

    /// Wrap an already-encoded Widevine payload in a version 0 box.
    ///
    /// Use this when something upstream — a licence service, a packager, a
    /// protobuf encoder — handed you the Widevine payload and all that is
    /// missing is the ISO-BMFF box around it.
    pub fn widevine_v0(data: impl Into<Vec<u8>>) -> Self {
        Self {
            version: 0,
            flags: [0; 3],
            system_id: WIDEVINE_SYSTEM_ID,
            key_ids: Vec::new(),
            data: data.into(),
        }
    }

    /// True if this box is for the Widevine system.
    pub fn is_widevine(&self) -> bool {
        self.system_id == WIDEVINE_SYSTEM_ID
    }

    /// Serialise to the on-the-wire `pssh` box, size field included.
    ///
    /// Key IDs are only written for version 1; setting `key_ids` on a version 0
    /// box has no effect on the output, matching what a version 0 box can
    /// represent.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(HEADER_LEN + 4 + self.key_ids.len() * KEY_ID_LEN + self.data.len());

        out.extend_from_slice(&[0, 0, 0, 0]); // size, patched below
        out.extend_from_slice(b"pssh");
        out.push(self.version);
        out.extend_from_slice(&self.flags);
        out.extend_from_slice(&self.system_id);

        if self.version >= 1 {
            out.extend_from_slice(&(self.key_ids.len() as u32).to_be_bytes());
            for key_id in &self.key_ids {
                out.extend_from_slice(key_id);
            }
        }

        out.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.data);

        let size = out.len() as u32;
        out[0..4].copy_from_slice(&size.to_be_bytes());
        out
    }

    /// Parse a `pssh` box.
    ///
    /// Trailing bytes past the box's own declared size are ignored, so this can
    /// be pointed at a buffer holding a box followed by other data. A declared
    /// size of `0` (meaning "to end of file") is treated as the whole slice.
    ///
    /// # Errors
    ///
    /// - [`Error::Truncated`] if the slice ends before the box header, the
    ///   declared box size, the key ID list or the payload.
    /// - [`Error::Malformed`] if the box type is not `pssh`, or if the box uses
    ///   the 64-bit `largesize` form, which is not supported.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated {
                what: "pssh box",
                needed: HEADER_LEN,
                available: bytes.len(),
            });
        }

        if &bytes[4..8] != b"pssh" {
            return Err(Error::Malformed {
                what: "pssh box",
                detail: "box type is not 'pssh'",
            });
        }

        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if declared == 1 {
            return Err(Error::Malformed {
                what: "pssh box",
                detail: "64-bit largesize boxes are not supported",
            });
        }

        // A declared size of 0 means "runs to the end of the buffer".
        let bytes = if declared == 0 {
            bytes
        } else {
            if declared > bytes.len() {
                return Err(Error::Truncated {
                    what: "pssh box",
                    needed: declared,
                    available: bytes.len(),
                });
            }
            if declared < HEADER_LEN {
                return Err(Error::Malformed {
                    what: "pssh box",
                    detail: "declared box size is smaller than the header",
                });
            }
            &bytes[..declared]
        };

        let version = bytes[8];
        let flags = [bytes[9], bytes[10], bytes[11]];
        let mut system_id = [0u8; 16];
        system_id.copy_from_slice(&bytes[12..28]);

        let mut offset = 28;
        let mut key_ids = Vec::new();

        if version >= 1 {
            let count = read_u32(bytes, offset, "pssh key ID count")? as usize;
            offset += 4;

            let needed = count
                .checked_mul(KEY_ID_LEN)
                .and_then(|n| n.checked_add(offset))
                .ok_or(Error::Malformed {
                    what: "pssh box",
                    detail: "key ID count overflows the addressable range",
                })?;
            if needed > bytes.len() {
                return Err(Error::Truncated {
                    what: "pssh key ID list",
                    needed,
                    available: bytes.len(),
                });
            }

            key_ids.reserve(count);
            for _ in 0..count {
                let mut key_id = [0u8; KEY_ID_LEN];
                key_id.copy_from_slice(&bytes[offset..offset + KEY_ID_LEN]);
                key_ids.push(key_id);
                offset += KEY_ID_LEN;
            }
        }

        let data_len = read_u32(bytes, offset, "pssh data size")? as usize;
        offset += 4;

        let end = offset.checked_add(data_len).ok_or(Error::Malformed {
            what: "pssh box",
            detail: "data size overflows the addressable range",
        })?;
        if end > bytes.len() {
            return Err(Error::Truncated {
                what: "pssh data",
                needed: end,
                available: bytes.len(),
            });
        }

        Ok(Self {
            version,
            flags,
            system_id,
            key_ids,
            data: bytes[offset..end].to_vec(),
        })
    }
}

/// Read a big-endian `u32`, reporting truncation rather than panicking.
fn read_u32(bytes: &[u8], offset: usize, what: &'static str) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::Malformed {
        what,
        detail: "offset overflows the addressable range",
    })?;
    if end > bytes.len() {
        return Err(Error::Truncated {
            what,
            needed: end,
            available: bytes.len(),
        });
    }
    Ok(u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}
