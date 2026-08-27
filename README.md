# drm-primitives

Rust building blocks for DRM-protected streaming:

- **Generate a Widevine PSSH box in Rust**, version 1 (key IDs in the clear) or
  version 0 (an opaque payload you already have).
- **Parse a PSSH box** from its bytes and read its version, system ID and key
  IDs back. `PsshBox::parse` takes the box itself — finding it inside a `moov`
  and base64-decoding a DASH `<cenc:pssh>` element are the caller's job.
- **AES-128 HLS segment encryption** — AES-128-CBC with PKCS#7, plus key and IV
  generation from the OS CSPRNG.
- **HKDF-SHA256 content-key derivation**, so a key service can recompute a
  content key from a master key and a key ID instead of storing it.
- **FairPlay certificate handling** and `#EXT-X-KEY` / `#EXT-X-SESSION-KEY` tag
  parsing.

No async runtime, no network, no configuration. Every function takes bytes and
returns bytes.

## Install

```toml
[dependencies]
drm-primitives = "0.1"
```

## Widevine PSSH boxes

```rust
use drm_primitives::widevine::{PsshBox, WIDEVINE_SYSTEM_ID};

let key_id = [0x0au8; 16];

// Version 1: the key IDs are listed in the box, readable without a
// protobuf decoder.
let bytes = PsshBox::widevine_v1(&[key_id]).to_bytes();

let parsed = PsshBox::parse(&bytes).unwrap();
assert!(parsed.is_widevine());
assert_eq!(parsed.system_id, WIDEVINE_SYSTEM_ID);
assert_eq!(parsed.key_ids, vec![key_id]);
```

If you already hold an encoded Widevine payload — from a licence service, a
packager, or your own protobuf encoder — `PsshBox::widevine_v0(payload)` puts
the ISO-BMFF box around it.

The parser is system-agnostic on purpose. It reads a PlayReady box, or any
other, and reports the system ID it found; `is_widevine()` is the check. It
rejects a truncated box, a box whose declared size runs past the buffer, and a
key ID count large enough to overflow the length arithmetic, rather than
indexing into whatever follows.

## AES-128 segment encryption

```rust
use drm_primitives::crypto::{aes_128_cbc_decrypt, aes_128_cbc_encrypt, generate_aes_key, generate_iv};

let key = generate_aes_key().unwrap();
let iv = generate_iv().unwrap();

let ciphertext = aes_128_cbc_encrypt(&key, &iv, b"...transport stream bytes...").unwrap();
let plaintext = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

assert_eq!(plaintext, b"...transport stream bytes...");
```

Padding is validated on the way back, so a wrong key is an `InvalidPadding`
error rather than a plaintext quietly short by however many bytes the last one
happened to name. A key or IV that is not 16 bytes is an error, not a panic.

## Key derivation

```rust
use drm_primitives::crypto::derive_key;

// Same master key and key ID, same content key — every time, on every host.
let content_key = derive_key(b"master key material", b"asset-1").unwrap();

assert_eq!(content_key, derive_key(b"master key material", b"asset-1").unwrap());
assert_ne!(content_key, derive_key(b"master key material", b"asset-2").unwrap());
```

HKDF-SHA256, with the key ID as the `info` string and no salt. Distinct key IDs
give unrelated content keys under one master key, which is what makes a key
service able to answer for an asset it has never stored a key for.

## FairPlay and EXT-X-KEY

```rust
use drm_primitives::fairplay::HlsKeyParser;

let tag = r#"#EXT-X-KEY:METHOD=SAMPLE-AES,KEYFORMAT="com.apple.streamingkeydelivery",URI="skd://asset-1""#;
let info = HlsKeyParser::parse(tag).unwrap();

assert_eq!(info.method, "SAMPLE-AES");
assert_eq!(info.uri.as_deref(), Some("skd://asset-1"));
```

The attribute list is split on commas outside quotes. That is not a detail: a
key URI with a query string can contain a comma, and a parser that splits on
every `,` truncates the URI into something that still looks like it parsed.

`FairPlayCertificate::load_from_file` reads the DER certificate Apple issues to
a FairPlay Streaming deployment, and `extract_public_key` returns the
`SubjectPublicKeyInfo` out of it — the same bytes `openssl x509 -pubkey` prints,
in DER rather than PEM. It walks the certificate structure and bounds-checks
every length against the structure enclosing it.

It reads the certificate; it does not verify it. No signature, issuer or expiry
is checked, and nothing confirms the key inside is one Apple issued. If that
matters, verify the certificate with an X.509 crate first.

## What this crate does not do

Worth being blunt about, because the name attracts the wrong expectation:

- **It is not a licence server.** No licence issuing, no policy evaluation, no
  device authentication, no proxy, no key rotation schedule.
- **It does not talk to Widevine or FairPlay licence servers.** There is no
  network client here and no HTTP dependency. An earlier version of this code
  had one; it was removed rather than published, because it was a stub.
- **It does not decode the Widevine protobuf.** A version 0 PSSH payload is
  carried through as bytes.
- **It does not generate a FairPlay CKC.** Doing that correctly needs Apple's
  Key Security Module and the credentials issued with it, neither of which can
  live in an open-source crate.
- **It does not make content secure.** AES-128-CBC here is confidentiality
  only — there is no MAC, so a modified ciphertext decrypts to modified
  plaintext. HLS `METHOD=AES-128` hands the key to anyone your key endpoint
  answers. Actual protection comes from a CDM, a licence server, and the
  authentication in front of that endpoint. This crate builds the artefacts
  those systems exchange; it is not a substitute for any of them.
- **It does not validate certificates.** Loading one reads bytes off disk. No
  signature, issuer or expiry is checked.

## Compatibility

Rust 1.74 or newer. Dependencies are RustCrypto (`aes`, `cbc`, `cipher`,
`hkdf`, `sha2`), `base64`, `hex`, `getrandom` and `thiserror` — no TLS stack,
no async runtime.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please do not attach real certificates,
keys or licence payloads to an issue.

## License

MIT. See [LICENSE](LICENSE).
