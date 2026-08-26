//! FairPlay Streaming certificate handling and HLS `EXT-X-KEY` parsing.
//!
//! Two separate jobs live here because both sit on the FairPlay path:
//!
//! - [`FairPlayCertificate`] loads the DER certificate Apple issues to a
//!   FairPlay Streaming deployment and locates the public key inside it.
//! - [`HlsKeyParser`] reads an `#EXT-X-KEY` tag out of a playlist. It is not
//!   FairPlay-specific — it reads `METHOD=AES-128` and `METHOD=SAMPLE-AES`
//!   tags equally — but the FairPlay `skd://` URI is the reason it is here.
//!
//! ```
//! use drm_primitives::fairplay::HlsKeyParser;
//!
//! # fn main() -> Result<(), drm_primitives::Error> {
//! let tag = r#"#EXT-X-KEY:METHOD=SAMPLE-AES,KEYFORMAT="com.apple.streamingkeydelivery",URI="skd://asset-1""#;
//! let info = HlsKeyParser::parse(tag)?;
//!
//! assert_eq!(info.method, "SAMPLE-AES");
//! assert_eq!(info.uri.as_deref(), Some("skd://asset-1"));
//! # Ok(())
//! # }
//! ```

use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::{Error, Result};

/// Loading and inspecting the FairPlay Streaming certificate.
///
/// This is a unit struct used as a namespace; there is no state to hold.
pub struct FairPlayCertificate;

impl FairPlayCertificate {
    /// Read a DER-encoded FairPlay Streaming certificate from disk.
    ///
    /// The bytes are returned verbatim. Nothing here validates the
    /// certificate's signature, issuer or expiry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        Ok(std::fs::read(path.as_ref())?)
    }

    /// Locate the first DER `SEQUENCE` with a two-byte length inside a
    /// certificate and return it, header included.
    ///
    /// # This is a heuristic, not a DER parser
    ///
    /// It scans for the byte pair `30 82` — `SEQUENCE`, long-form length, two
    /// length bytes — and returns that structure. In an RSA certificate of the
    /// usual shape the outermost such structure is the one being looked for,
    /// which is why the trick works often enough to be useful. It has no idea
    /// what it found, and it will happily return a different `SEQUENCE` from a
    /// certificate laid out differently. If the identity of the key matters,
    /// parse the certificate with an X.509 crate instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if no such structure is found, or if the
    /// one that is found claims a length running past the end of the input.
    pub fn extract_public_key(certificate: &[u8]) -> Result<Vec<u8>> {
        let mut search_from = 0usize;

        while let Some(relative) = certificate[search_from..]
            .windows(2)
            .position(|window| window == [0x30, 0x82])
        {
            let start = search_from + relative;

            // Need the two length bytes that follow the 0x30 0x82 pair.
            if start + 4 <= certificate.len() {
                let len =
                    u16::from_be_bytes([certificate[start + 2], certificate[start + 3]]) as usize;
                if let Some(end) = start.checked_add(4).and_then(|s| s.checked_add(len)) {
                    if end <= certificate.len() {
                        return Ok(certificate[start..end].to_vec());
                    }
                }
            }

            search_from = start + 1;
            if search_from + 2 > certificate.len() {
                break;
            }
        }

        Err(Error::Malformed {
            what: "FairPlay certificate",
            detail: "no DER SEQUENCE with a two-byte length was found",
        })
    }
}

/// The two identifiers carried in a 16-byte FairPlay initialisation blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpsInitData {
    /// The first eight bytes, base64-encoded.
    pub content_id: String,
    /// The next eight bytes, base64-encoded.
    pub key_id: String,
}

impl FpsInitData {
    /// Split a 16-byte FairPlay initialisation blob into its two halves.
    ///
    /// The layout this assumes is eight bytes of content ID followed by eight
    /// bytes of key ID, each returned base64-encoded so it can go straight into
    /// a URI or a JSON body. Bytes past the first sixteen are ignored.
    ///
    /// The layout is a convention, not something the format guarantees — it is
    /// whatever the packager that produced the blob wrote. Check against your
    /// own packager before relying on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if fewer than 16 bytes are supplied.
    ///
    /// ```
    /// use drm_primitives::fairplay::FpsInitData;
    ///
    /// # fn main() -> Result<(), drm_primitives::Error> {
    /// let blob = [0u8; 16];
    /// let parsed = FpsInitData::parse(&blob)?;
    /// assert_eq!(parsed.content_id, "AAAAAAAAAAA=");
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(init_data: &[u8]) -> Result<Self> {
        if init_data.len() < 16 {
            return Err(Error::Truncated {
                what: "FairPlay init data",
                needed: 16,
                available: init_data.len(),
            });
        }

        Ok(Self {
            content_id: STANDARD.encode(&init_data[..8]),
            key_id: STANDARD.encode(&init_data[8..16]),
        })
    }
}

/// The attributes of one `#EXT-X-KEY` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlsKeyInfo {
    /// `METHOD` — `NONE`, `AES-128`, `SAMPLE-AES`, or a vendor value.
    pub method: String,
    /// `URI`, where the key or licence is fetched from. Absent when the method
    /// is `NONE`, which is how a playlist declares that encryption stops.
    pub uri: Option<String>,
    /// `IV`, decoded from its `0x` hex form. Always 16 bytes when present.
    pub iv: Option<Vec<u8>>,
    /// `KEYFORMAT`, e.g. `com.apple.streamingkeydelivery` for FairPlay.
    pub key_format: Option<String>,
    /// `KEYFORMATVERSIONS`, verbatim — it is a slash-separated list.
    pub key_format_versions: Option<String>,
}

/// Parsing of the HLS `#EXT-X-KEY` tag (RFC 8216 section 4.3.2.4).
///
/// This is a unit struct used as a namespace; there is no state to hold.
pub struct HlsKeyParser;

impl HlsKeyParser {
    /// Parse an `#EXT-X-KEY` tag.
    ///
    /// The attribute list is split on commas that are **outside** quotes, which
    /// matters more than it sounds: a key URI with a query string can contain
    /// commas, and a naive split on `,` truncates the URI and produces a tag
    /// that looks like it parsed.
    ///
    /// Unknown attributes are ignored, as RFC 8216 requires of a parser.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] if the tag is not an `EXT-X-KEY` tag, if `METHOD`
    ///   is absent, or if a present `IV` is not 16 bytes once decoded.
    /// - [`Error::Hex`] if `IV` is not valid hex.
    ///
    /// ```
    /// use drm_primitives::fairplay::HlsKeyParser;
    ///
    /// # fn main() -> Result<(), drm_primitives::Error> {
    /// let tag = concat!(
    ///     r#"#EXT-X-KEY:METHOD=AES-128,URI="https://keys.example/k?id=1,2","#,
    ///     "IV=0x1234567890ABCDEF1234567890ABCDEF",
    /// );
    /// let info = HlsKeyParser::parse(tag)?;
    ///
    /// // The comma inside the quoted URI did not split the attribute.
    /// assert_eq!(info.uri.as_deref(), Some("https://keys.example/k?id=1,2"));
    /// assert_eq!(info.iv.map(|iv| iv.len()), Some(16));
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(tag: &str) -> Result<HlsKeyInfo> {
        let tag = tag.trim();
        let attributes = tag
            .strip_prefix("#EXT-X-KEY:")
            .or_else(|| tag.strip_prefix("#EXT-X-SESSION-KEY:"))
            .ok_or(Error::Malformed {
                what: "EXT-X-KEY tag",
                detail: "tag does not start with #EXT-X-KEY: or #EXT-X-SESSION-KEY:",
            })?;

        let mut method = None;
        let mut uri = None;
        let mut iv = None;
        let mut key_format = None;
        let mut key_format_versions = None;

        for attribute in split_outside_quotes(attributes) {
            let Some((name, value)) = attribute.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim().trim_matches('"');

            match name {
                "METHOD" => method = Some(value.to_string()),
                "URI" => uri = Some(value.to_string()),
                "KEYFORMAT" => key_format = Some(value.to_string()),
                "KEYFORMATVERSIONS" => key_format_versions = Some(value.to_string()),
                "IV" => {
                    let hex_digits = value
                        .strip_prefix("0x")
                        .or_else(|| value.strip_prefix("0X"))
                        .unwrap_or(value);
                    let decoded = hex::decode(hex_digits)?;
                    if decoded.len() != 16 {
                        return Err(Error::Malformed {
                            what: "EXT-X-KEY IV",
                            detail: "IV must decode to exactly 16 bytes",
                        });
                    }
                    iv = Some(decoded);
                }
                _ => {}
            }
        }

        Ok(HlsKeyInfo {
            method: method.ok_or(Error::Malformed {
                what: "EXT-X-KEY tag",
                detail: "METHOD attribute is required",
            })?,
            uri,
            iv,
            key_format,
            key_format_versions,
        })
    }
}

/// Split an HLS attribute list on commas that are not inside a quoted string.
fn split_outside_quotes(attributes: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (index, character) in attributes.char_indices() {
        match character {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(&attributes[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&attributes[start..]);
    parts
}
