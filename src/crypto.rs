//! AES-128-CBC encryption, key and IV generation, and HKDF key derivation.
//!
//! These are the pieces an HLS packager needs to produce `METHOD=AES-128`
//! segments and the pieces a key service needs to derive a per-asset content
//! key from a long-lived master key.
//!
//! ```
//! use drm_primitives::crypto::{aes_128_cbc_decrypt, aes_128_cbc_encrypt, generate_aes_key, generate_iv};
//!
//! # fn main() -> Result<(), drm_primitives::Error> {
//! let key = generate_aes_key()?;
//! let iv = generate_iv()?;
//!
//! let ciphertext = aes_128_cbc_encrypt(&key, &iv, b"a transport stream segment")?;
//! let plaintext = aes_128_cbc_decrypt(&key, &iv, &ciphertext)?;
//!
//! assert_eq!(plaintext, b"a transport stream segment");
//! # Ok(())
//! # }
//! ```

use aes::Aes128;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};

/// The AES block size in bytes. CBC ciphertexts are always a multiple of this.
pub const AES_BLOCK_SIZE: usize = 16;

/// The length of an AES-128 key in bytes.
pub const AES_128_KEY_LEN: usize = 16;

/// The length of a CBC initialisation vector in bytes.
pub const AES_IV_LEN: usize = 16;

type Encryptor = cbc::Encryptor<Aes128>;
type Decryptor = cbc::Decryptor<Aes128>;

/// Read exactly 16 bytes out of a slice, or say which value was the wrong size.
fn exactly_16(bytes: &[u8], what: &'static str) -> Result<[u8; 16]> {
    bytes.try_into().map_err(|_| Error::InvalidLength {
        what,
        expected: 16,
        actual: bytes.len(),
    })
}

/// Generate a random 128-bit AES key from the operating system CSPRNG.
///
/// # Errors
///
/// Returns [`Error::Rng`] if the OS random source is unavailable — on a normal
/// hosted platform this does not happen, but it is reported rather than
/// panicked on, because a silently weak key is the worst failure mode here.
///
/// ```
/// # fn main() -> Result<(), drm_primitives::Error> {
/// let key = drm_primitives::crypto::generate_aes_key()?;
/// assert_eq!(key.len(), 16);
/// # Ok(())
/// # }
/// ```
pub fn generate_aes_key() -> Result<[u8; AES_128_KEY_LEN]> {
    let mut key = [0u8; AES_128_KEY_LEN];
    getrandom::fill(&mut key)?;
    Ok(key)
}

/// Generate a random 128-bit initialisation vector from the OS CSPRNG.
///
/// Use a fresh IV for every segment. Reusing one across segments encrypted
/// under the same key leaks whether two segments share a leading block.
///
/// # Errors
///
/// Returns [`Error::Rng`] if the OS random source is unavailable.
pub fn generate_iv() -> Result<[u8; AES_IV_LEN]> {
    let mut iv = [0u8; AES_IV_LEN];
    getrandom::fill(&mut iv)?;
    Ok(iv)
}

/// Encrypt with AES-128-CBC and PKCS#7 padding.
///
/// The output is always a whole number of 16-byte blocks and is always at
/// least one block longer than an input that is an exact multiple of the block
/// size — that trailing block is the padding, and it is what makes the length
/// unambiguous on the way back.
///
/// This is confidentiality only. There is no MAC, so a modified ciphertext
/// decrypts to modified plaintext rather than to an error. If the ciphertext
/// travels somewhere it can be tampered with, authenticate it separately.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] if `key` or `iv` is not 16 bytes.
///
/// ```
/// use drm_primitives::crypto::aes_128_cbc_encrypt;
///
/// # fn main() -> Result<(), drm_primitives::Error> {
/// let ciphertext = aes_128_cbc_encrypt(&[0x11; 16], &[0x22; 16], b"0123456789abcdef")?;
/// // 16 bytes of input plus a full block of padding.
/// assert_eq!(ciphertext.len(), 32);
/// # Ok(())
/// # }
/// ```
pub fn aes_128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = exactly_16(key, "AES-128 key")?;
    let iv = exactly_16(iv, "AES-CBC IV")?;

    Ok(Encryptor::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// Decrypt AES-128-CBC and strip PKCS#7 padding.
///
/// The padding is validated, not assumed. A wrong key, a wrong IV or an
/// altered final block is reported as [`Error::InvalidPadding`] instead of
/// silently truncating the plaintext by whatever the last byte happened to be.
///
/// # Errors
///
/// - [`Error::InvalidLength`] if `key` or `iv` is not 16 bytes.
/// - [`Error::UnalignedCiphertext`] if `ciphertext` is not a multiple of 16.
/// - [`Error::InvalidPadding`] if the trailing PKCS#7 padding is not valid.
///
/// # A note on padding oracles
///
/// Do not expose the difference between [`Error::InvalidPadding`] and a
/// downstream parse failure to an untrusted caller. An attacker who can tell
/// those two apart, and who can make repeated calls, can recover plaintext
/// without the key. Authenticate the ciphertext, or collapse every failure
/// into one opaque response.
pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = exactly_16(key, "AES-128 key")?;
    let iv = exactly_16(iv, "AES-CBC IV")?;

    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::UnalignedCiphertext(ciphertext.len()));
    }

    Decryptor::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::InvalidPadding)
}

/// Derive a 128-bit content key from a master key and a key ID, using
/// HKDF-SHA256.
///
/// `master_key` is the input keying material and `key_id` is the `info`
/// string, so distinct key IDs give unrelated content keys under the same
/// master key, and the same pair always gives the same key — which is what
/// lets a key service recompute a content key instead of storing it.
///
/// No salt is used. That is the standard choice when the input keying material
/// is already a uniformly random secret, and it keeps the derivation
/// reproducible from `(master_key, key_id)` alone with nothing else to persist.
///
/// # Errors
///
/// Returns [`Error::EmptyInput`] if `master_key` is empty. An empty `key_id` is
/// allowed — HKDF permits an empty `info`.
///
/// ```
/// use drm_primitives::crypto::derive_key;
///
/// # fn main() -> Result<(), drm_primitives::Error> {
/// let a = derive_key(b"master key material", b"asset-1")?;
/// let b = derive_key(b"master key material", b"asset-1")?;
/// let c = derive_key(b"master key material", b"asset-2")?;
///
/// assert_eq!(a, b);
/// assert_ne!(a, c);
/// # Ok(())
/// # }
/// ```
pub fn derive_key(master_key: &[u8], key_id: &[u8]) -> Result<[u8; AES_128_KEY_LEN]> {
    if master_key.is_empty() {
        return Err(Error::EmptyInput("master key"));
    }

    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut derived = [0u8; AES_128_KEY_LEN];

    // 16 bytes is far below HKDF-SHA256's 255 * 32 byte output limit, so this
    // branch is unreachable; it is mapped rather than unwrapped so a future
    // change to the output length cannot turn into a panic.
    hkdf.expand(key_id, &mut derived)
        .map_err(|_| Error::Malformed {
            what: "HKDF expansion",
            detail: "requested output length is not supported",
        })?;

    Ok(derived)
}
