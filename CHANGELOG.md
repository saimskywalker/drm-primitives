# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`FairPlayCertificate::extract_public_key` returns the public key.** It
  scanned for the first `30 82` byte pair — `SEQUENCE`, long-form length — and
  returned the structure it found. In any DER X.509 certificate the outermost
  such structure is the certificate itself, so given a real certificate the
  function returned its whole input, and a caller who sent the result where a
  public key was expected sent the entire file. It now walks the certificate to
  `tbsCertificate.subjectPublicKeyInfo` and returns that, bounds-checking every
  DER length against the structure enclosing it. The tests cover a v1
  certificate, a v3 certificate (where the optional explicit `version` field
  has to be skipped) and a P-256 certificate whose key uses a short-form DER
  length, which the old scan could not have found at all.
- The certificate reader rejects the indefinite DER length form, a length field
  wider than a machine word, and any field that runs past the structure
  enclosing it, rather than reading into the signature that follows.

### Documentation

- The README no longer says the crate parses a `pssh` box out of a `moov`, a
  DASH `<cenc:pssh>` element or a base64 blob. `PsshBox::parse` takes the box
  bytes; locating and decoding them is the caller's job.


## [0.1.0] - 2026-08-27

First release. The code was extracted from a private streaming backend, where
it had been in production use; the parts of it that talked to a network or
stood in for cryptography it did not perform were removed rather than
published.

### Added

- `crypto` — AES-128-CBC encryption and decryption with PKCS#7 padding, key
  and IV generation from the OS CSPRNG, and HKDF-SHA256 content-key derivation.
- `widevine` — `PsshBox` generation and parsing for ISO/IEC 23001-7 `pssh`
  boxes, version 0 and version 1, with the registered Widevine system ID.
- `fairplay` — FairPlay Streaming certificate loading and DER public-key
  extraction, FPS initialisation data splitting, and `#EXT-X-KEY` /
  `#EXT-X-SESSION-KEY` tag parsing.
- `Error`, one `#[non_exhaustive]` error type for the whole crate.

### Changed from the code this was extracted from

- **Key derivation is HKDF-SHA256.** It had been a byte-wise XOR of the master
  key against the key ID, which is reversible by anyone holding either input.
- **CBC uses the RustCrypto `cbc` crate.** The hand-rolled loop it replaces
  truncated by the final byte on decryption without validating the padding, so
  a wrong key silently produced a wrong-length plaintext instead of an error.
- **Lengths are checked.** A key or IV that was not 16 bytes used to panic
  inside `GenericArray::from_slice`; it is now `Error::InvalidLength`.
- **Every parser is bounds-checked.** The `pssh` and certificate readers
  indexed on values taken from their own input, so a malformed box could panic.
- **Errors are a `thiserror` enum, not `anyhow::Error`**, so callers can match
  on a failure instead of formatting it.
- `EXT-X-KEY` attributes are split on commas outside quotes. A key URI with a
  comma in its query string used to be truncated into a tag that still parsed.

### Removed

- The Widevine licence-server client, which fetched licences over HTTP and
  signed requests with a construction its own comment described as
  provisional. It was the only reason the crate depended on `reqwest`.
- The FairPlay CKC generator, whose "RSA-encrypted" content key was the
  content key copied into a 128-byte buffer in the clear.
- The Widevine licence request and response codec, which claimed to read and
  write protobuf and did neither.

[Unreleased]: https://github.com/saimskywalker/drm-primitives/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saimskywalker/drm-primitives/releases/tag/v0.1.0
