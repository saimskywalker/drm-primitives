//! FairPlay Streaming certificate handling and HLS `EXT-X-KEY` parsing.
//!
//! Two separate jobs live here because both sit on the FairPlay path:
//!
//! - [`FairPlayCertificate`] loads the DER certificate Apple issues to a
//!   FairPlay Streaming deployment and extracts the `SubjectPublicKeyInfo`
//!   from it. It reads the certificate; it does not verify it.
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

    /// Extract the `SubjectPublicKeyInfo` from an X.509 certificate, DER
    /// header included.
    ///
    /// The output is the same bytes `openssl x509 -pubkey` would print, in DER
    /// rather than PEM — an `AlgorithmIdentifier` followed by the key itself,
    /// which is the form a key is normally handed to an RSA or EC
    /// implementation in.
    ///
    /// # What is and is not checked
    ///
    /// This walks the certificate far enough to find the field and no further:
    /// outer `SEQUENCE`, `tbsCertificate`, then past the optional
    /// `[0] EXPLICIT version` and the five fields before
    /// `subjectPublicKeyInfo`. Every length is bounds-checked against the
    /// structure that encloses it.
    ///
    /// It does **not** verify the certificate: no signature, no issuer, no
    /// expiry, and no check that the key inside is one Apple issued. It also
    /// does not decode the key — the `SubjectPublicKeyInfo` is returned as
    /// bytes, not as a modulus and exponent.
    ///
    /// # Errors
    ///
    /// - [`Error::Truncated`] if the certificate ends inside a DER structure
    ///   one of its own length fields promised.
    /// - [`Error::Malformed`] if the input is not shaped like an X.509
    ///   certificate, if a field runs past the structure enclosing it, or if a
    ///   DER length uses the indefinite form or is too wide to address.
    ///
    /// A real certificate is several hundred bytes, so the shape is easier to
    /// see in a skeleton one — a `tbsCertificate` holding the five fields that
    /// come before the key, and then the key:
    ///
    /// ```
    /// # fn main() -> Result<(), drm_primitives::Error> {
    /// use drm_primitives::fairplay::FairPlayCertificate;
    ///
    /// // SEQUENCE {                          -- Certificate
    /// //   SEQUENCE {                        -- tbsCertificate (v1: no version)
    /// //     INTEGER, INTEGER, INTEGER,      -- serialNumber, signature, issuer
    /// //     INTEGER, INTEGER,               -- validity, subject
    /// //     SEQUENCE { INTEGER 7 } } }      -- subjectPublicKeyInfo
    /// let certificate = [
    ///     0x30, 0x16, 0x30, 0x14, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02,
    ///     0x01, 0x03, 0x02, 0x01, 0x04, 0x02, 0x01, 0x05, 0x30, 0x03, 0x02,
    ///     0x01, 0x07,
    /// ];
    ///
    /// assert_eq!(
    ///     FairPlayCertificate::extract_public_key(&certificate)?,
    ///     [0x30, 0x03, 0x02, 0x01, 0x07],
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn extract_public_key(certificate: &[u8]) -> Result<Vec<u8>> {
        // Certificate ::= SEQUENCE {
        //     tbsCertificate       TBSCertificate,
        //     signatureAlgorithm   AlgorithmIdentifier,
        //     signatureValue       BIT STRING }
        let outer = read_tlv(certificate, 0)?;
        if outer.tag != DER_SEQUENCE {
            return Err(malformed_certificate(
                "the input does not begin with a DER SEQUENCE, so it is not an X.509 certificate",
            ));
        }

        let tbs = read_tlv(certificate, outer.start)?;
        if tbs.tag != DER_SEQUENCE {
            return Err(malformed_certificate("tbsCertificate is not a SEQUENCE"));
        }
        if tbs.end > outer.end {
            return Err(malformed_certificate(
                "tbsCertificate runs past the end of the certificate",
            ));
        }

        // TBSCertificate ::= SEQUENCE {
        //     version         [0] EXPLICIT Version DEFAULT v1,  -- absent in v1
        //     serialNumber        CertificateSerialNumber,
        //     signature           AlgorithmIdentifier,
        //     issuer              Name,
        //     validity            Validity,
        //     subject             Name,
        //     subjectPublicKeyInfo SubjectPublicKeyInfo,
        //     ... }
        //
        // Every field is read against `tbs.end` rather than the end of the
        // buffer, so a length that reaches past tbsCertificate is rejected
        // instead of walking into the signature that follows it.
        let mut offset = tbs.start;

        let first = read_field(certificate, offset, tbs.end)?;
        if first.tag == DER_CONTEXT_0 {
            offset = first.end;
        }

        for _ in 0..FIELDS_BEFORE_PUBLIC_KEY {
            offset = read_field(certificate, offset, tbs.end)?.end;
        }

        let spki = read_field(certificate, offset, tbs.end)?;
        if spki.tag != DER_SEQUENCE {
            return Err(malformed_certificate(
                "subjectPublicKeyInfo is not a SEQUENCE",
            ));
        }

        Ok(certificate[offset..spki.end].to_vec())
    }
}

/// The DER tag for a `SEQUENCE`, constructed.
const DER_SEQUENCE: u8 = 0x30;

/// The DER tag for `[0]`, context-specific and constructed — the optional
/// explicit `version` at the front of a v3 `tbsCertificate`.
const DER_CONTEXT_0: u8 = 0xA0;

/// `serialNumber`, `signature`, `issuer`, `validity` and `subject`: the five
/// fields sitting between the optional version and `subjectPublicKeyInfo`.
const FIELDS_BEFORE_PUBLIC_KEY: usize = 5;

/// One DER tag-length-value, located inside a buffer.
#[derive(Debug, Clone, Copy)]
struct Tlv {
    /// The identifier octet.
    tag: u8,
    /// Offset of the first content byte.
    start: usize,
    /// Offset one past the last content byte — also where the next TLV begins.
    end: usize,
}

fn malformed_certificate(detail: &'static str) -> Error {
    Error::Malformed {
        what: "FairPlay certificate",
        detail,
    }
}

/// Read the TLV at `offset` and require it to fit inside its parent structure.
fn read_field(bytes: &[u8], offset: usize, parent_end: usize) -> Result<Tlv> {
    let field = read_tlv(bytes, offset)?;
    if field.end > parent_end {
        return Err(malformed_certificate(
            "a certificate field runs past the structure enclosing it",
        ));
    }
    Ok(field)
}

/// Read one DER tag-length-value header, reporting truncation and unusable
/// lengths rather than indexing on numbers taken from the input.
fn read_tlv(bytes: &[u8], offset: usize) -> Result<Tlv> {
    let truncated = |needed: usize| Error::Truncated {
        what: "FairPlay certificate",
        needed,
        available: bytes.len(),
    };

    let tag = *bytes.get(offset).ok_or_else(|| truncated(offset + 1))?;
    if tag & 0x1F == 0x1F {
        return Err(malformed_certificate(
            "high-tag-number form identifiers are not supported",
        ));
    }

    let first_length_byte = *bytes.get(offset + 1).ok_or_else(|| truncated(offset + 2))?;
    let (length, header_len) = if first_length_byte < 0x80 {
        // Short form: the byte is the length.
        (first_length_byte as usize, 2)
    } else {
        // Long form: the low seven bits count the length bytes that follow.
        let count = (first_length_byte & 0x7F) as usize;
        if count == 0 {
            // 0x80 is the indefinite form. Legal BER, never legal DER, and
            // it has no length to bounds-check against.
            return Err(malformed_certificate(
                "indefinite DER lengths are not valid in a certificate",
            ));
        }
        if count > core::mem::size_of::<usize>() {
            return Err(malformed_certificate(
                "a DER length field wider than a machine word cannot be addressed",
            ));
        }

        let from = offset + 2;
        let to = from + count;
        let raw = bytes.get(from..to).ok_or_else(|| truncated(to))?;

        // `count` is at most `size_of::<usize>()`, so this shifts in exactly
        // as many bytes as a `usize` holds and cannot overflow.
        let length = raw
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
        (length, 2 + count)
    };

    let start = offset
        .checked_add(header_len)
        .ok_or_else(|| malformed_certificate("a DER header overflows the addressable range"))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| malformed_certificate("a DER length overflows the addressable range"))?;
    if end > bytes.len() {
        return Err(truncated(end));
    }

    Ok(Tlv { tag, start, end })
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
