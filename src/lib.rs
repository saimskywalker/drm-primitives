//! Building blocks for DRM-protected streaming: Widevine `pssh` boxes,
//! AES-128-CBC segment encryption, HKDF content-key derivation, FairPlay
//! certificate handling and HLS `EXT-X-KEY` parsing.
//!
//! Each module is independent — nothing here needs a runtime, a network, a
//! configuration file or a background task. Give it bytes, get bytes back.
//!
//! - [`crypto`] — AES-128-CBC with PKCS#7, key and IV generation, HKDF-SHA256
//!   key derivation.
//! - [`widevine`] — `pssh` box generation and parsing (ISO/IEC 23001-7).
//! - [`fairplay`] — FairPlay Streaming certificate handling, FPS
//!   initialisation data, and `#EXT-X-KEY` parsing.
//!
//! # Example
//!
//! Encrypt a segment, then publish the key ID in a `pssh` box:
//!
//! ```
//! use drm_primitives::crypto::{aes_128_cbc_encrypt, derive_key, generate_iv};
//! use drm_primitives::widevine::PsshBox;
//!
//! # fn main() -> Result<(), drm_primitives::Error> {
//! let key_id = [0x42u8; 16];
//!
//! // The content key is derived, so it never has to be stored — the master
//! // key and the key ID recompute it.
//! let content_key = derive_key(b"master key material", &key_id)?;
//! let iv = generate_iv()?;
//!
//! let segment = aes_128_cbc_encrypt(&content_key, &iv, b"...transport stream bytes...")?;
//! let pssh = PsshBox::widevine_v1(&[key_id]).to_bytes();
//!
//! assert_eq!(segment.len() % 16, 0);
//! assert_eq!(&pssh[4..8], b"pssh");
//! # Ok(())
//! # }
//! ```
//!
//! # What this crate does not do
//!
//! It is a set of primitives, and the boundary is worth being explicit about:
//!
//! - **It is not a licence server.** There is no licence issuing, no policy
//!   evaluation, no device authentication, no proxy.
//! - **It does not talk to Widevine or FairPlay licence servers.** No network
//!   client, no HTTP dependency.
//! - **It does not decode the Widevine protobuf.** A version 0 `pssh` payload
//!   is carried verbatim as bytes.
//! - **It does not make content secure.** AES-128-CBC here is
//!   confidentiality only — no MAC — and HLS `AES-128` gives the key to
//!   anyone the key endpoint answers. Real protection comes from a CDM, a
//!   licence server and the authentication in front of the key endpoint;
//!   this crate builds the artefacts those systems exchange.
//! - **It does not validate certificates.** Loading a FairPlay certificate
//!   reads bytes off disk; it checks no signature, issuer or expiry.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod fairplay;
pub mod widevine;

pub use error::{Error, Result};

/// Compiles and runs the Rust examples in `README.md` as doctests, so the
/// front page cannot drift away from the API. Not part of the public API and
/// not built outside `cargo test`.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeExamples;
